"""shield-probe — vòng đời của agent nhỏ.

    shield-probe run       đọc log, đưa vào spool, gửi về Shield
    shield-probe status    xem còn tồn bao nhiêu dòng, lần gửi cuối ra sao
    shield-probe test      thử kết nối mTLS mà không gửi log thật

Probe CHỈ ĐỌC. Không có lệnh nào ở đây đụng vào nftables, process hay file
của hệ thống — xem probe/__init__.py.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import socket
import sys
import time
from pathlib import Path

from probe import config as config_module
from probe.reader import (
    FileLogReader,
    JournalReader,
    ReaderState,
    audit_record_to_event,
    file_line_to_event,
    journal_record_to_event,
)
from probe.shipper import Shipper
from probe.spool import Spool

logger = logging.getLogger("shield.probe")

POLL_INTERVAL_S = 5.0
# Backoff khi server không nối được. Trần 5 phút: probe không được biến thành
# thứ gõ cửa server mỗi giây khi server đang gặp sự cố.
BACKOFF_START_S = 5.0
BACKOFF_MAX_S = 300.0

_STOP = False


def _handle_signal(_signum, _frame) -> None:
    global _STOP
    _STOP = True


class Probe:
    def __init__(self, cfg) -> None:
        self.config = cfg
        state_dir = Path(cfg.spool_dir).parent
        self.spool = Spool(Path(cfg.spool_dir), cfg.spool_max_bytes)
        self.state = ReaderState(state_dir / "reader-state.json")
        self.journal = JournalReader(state_dir, cfg.journal_identifiers,
                                     include_audit=getattr(cfg, "include_audit", True))
        self.files = [FileLogReader(Path(p), self.state) for p in cfg.log_files]
        self.shipper = Shipper(cfg)
        self.hostname = socket.gethostname()
        self.collected = 0
        self.backoff = BACKOFF_START_S

    # --- thu thập ---------------------------------------------------------
    def collect(self) -> int:
        """Đọc log mới vào spool. Con trỏ chỉ tiến SAU khi đã ghi spool."""
        collected = 0
        budget = self.config.rate_per_s * POLL_INTERVAL_S

        for record in self.journal.read_new_records(max_lines=int(budget)):
            self.spool.append(journal_record_to_event(record, self.config.probe_id, self.hostname))
            collected += 1

        # Audit đi qua journald nhưng KHÔNG lọc theo --identifier được, nên
        # phải là một lượt đọc riêng với con trỏ riêng. Lọc ngay tại đây:
        # audit trên máy bận sinh hàng nghìn dòng mỗi giây.
        for record in self.journal.read_new_audit_records(max_lines=int(budget)):
            event = audit_record_to_event(record, self.config.probe_id, self.hostname)
            if event is None:
                continue
            self.spool.append(event)
            collected += 1

        for reader in self.files:
            lines = reader.read_new_lines(max_lines=int(budget))
            for line in lines:
                self.spool.append(
                    file_line_to_event(line, reader.path, self.config.probe_id, self.hostname)
                )
                collected += 1
            if lines:
                reader.commit()

        self.collected += collected
        return collected

    # --- gửi --------------------------------------------------------------
    def ship(self) -> tuple[bool, int]:
        records, _bytes = self.spool.read_batch(self.config.batch_lines, self.config.batch_bytes)
        if not records:
            return True, 0
        ok, accepted, message = self.shipper.send(records)
        if not ok:
            logger.warning("gửi thất bại (%s) — giữ lại %d dòng trong spool",
                           message, self.spool.pending_lines())
            return False, 0
        # Chỉ xoá sau khi server xác nhận. Mạng đứt giữa chừng thì gửi lại —
        # thà trùng còn hơn mất.
        self.spool.commit(accepted)
        return True, accepted

    def run_once(self) -> dict:
        collected = self.collect()
        ok, shipped = self.ship()
        if ok:
            self.backoff = BACKOFF_START_S
        else:
            self.backoff = min(BACKOFF_MAX_S, self.backoff * 2)
        return {"collected": collected, "shipped": shipped, "ok": ok,
                "pending": self.spool.pending_lines(), "dropped": self.spool.dropped}

    def run_forever(self) -> int:
        logger.info("shield-probe khởi động — gửi tới %s:%d, spool %s",
                    self.config.server_host, self.config.server_port, self.config.spool_dir)
        while not _STOP:
            try:
                result = self.run_once()
                if result["collected"] or result["shipped"]:
                    logger.info("đọc %d, gửi %d, còn tồn %d",
                                result["collected"], result["shipped"], result["pending"])
            except Exception:  # noqa: BLE001 - probe phải sống sót qua mọi lỗi lẻ
                logger.exception("vòng lặp probe gặp lỗi — thử lại")
            time.sleep(POLL_INTERVAL_S if self.backoff <= BACKOFF_START_S else self.backoff)
        logger.info("shield-probe dừng theo tín hiệu")
        return 0

    def status(self) -> dict:
        return {
            "probe_id": self.config.probe_id,
            "server": f"{self.config.server_host}:{self.config.server_port}",
            "pending_lines": self.spool.pending_lines(),
            "spool_bytes": self.spool.size_bytes(),
            "spool_max_bytes": self.config.spool_max_bytes,
            "dropped_lines": self.spool.dropped,
            "shipped_total": self.shipper.sent,
            "failures": self.shipper.failures,
            "last_error": self.shipper.last_error,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shield-probe",
        description="Đọc log của máy này và gửi về Shield. Chỉ đọc, không bao giờ hành động.",
    )
    parser.add_argument("command", choices=("run", "status", "test"))
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        cfg = config_module.load(args.config)
        cfg.validate()
    except (OSError, ValueError) as exc:
        print(f"Cấu hình probe không dùng được: {exc}", file=sys.stderr)
        print(f"Sửa tại: {args.config or config_module.config_path()}", file=sys.stderr)
        return 2

    probe = Probe(cfg)
    if args.command == "status":
        print(json.dumps(probe.status(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "test":
        ok, _accepted, message = probe.shipper.send([{
            "ts": time.time(), "source": "probe", "kind": "log_line",
            "data": {"message": "shield-probe connectivity test"},
        }])
        print("OK — kết nối mTLS tới Shield thành công" if ok else f"THẤT BẠI — {message}")
        return 0 if ok else 1
    return probe.run_forever()


if __name__ == "__main__":
    sys.exit(main())
