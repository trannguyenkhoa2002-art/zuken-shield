"""Buffer trên đĩa cho probe: mất mạng thì giữ lại, có mạng lại thì gửi bù.

Nguyên tắc quan trọng nhất ở đây: **im lặng mất log là điều tệ nhất một hệ
thống bằng chứng có thể làm**. Khi spool đầy, probe bỏ dòng CŨ NHẤT và ghi
thêm một bản ghi tự tố cáo (`probe_spool_overflow`) để phía Shield biết có
một khoảng trống — thà biết mình mù còn hơn tưởng mình thấy hết.

Định dạng: các file NDJSON xoay vòng trong một thư mục. Không dùng SQLite —
probe phải nhẹ, và ghi thêm vào cuối file là thao tác rẻ nhất, an toàn nhất
khi bị cắt điện giữa chừng (dòng cụt bị bỏ lúc đọc, không hỏng cả kho).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger("shield.probe.spool")

SEGMENT_PREFIX = "spool-"
SEGMENT_SUFFIX = ".ndjson"
DEFAULT_SEGMENT_BYTES = 4 * 1024 * 1024


class Spool:
    def __init__(self, directory: Path, max_bytes: int, segment_bytes: int = DEFAULT_SEGMENT_BYTES) -> None:
        self.directory = Path(directory)
        self.max_bytes = max(segment_bytes * 2, int(max_bytes))
        self.segment_bytes = int(segment_bytes)
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.dropped = 0

    # --- trạng thái -------------------------------------------------------
    def segments(self) -> list[Path]:
        return sorted(self.directory.glob(f"{SEGMENT_PREFIX}*{SEGMENT_SUFFIX}"))

    def size_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.segments() if path.exists())

    def _active_segment(self) -> Path:
        existing = self.segments()
        if existing and existing[-1].stat().st_size < self.segment_bytes:
            return existing[-1]
        # Thời gian + đếm để tên luôn tăng dần kể cả khi ghi nhiều lần trong
        # cùng một giây.
        stamp = f"{time.time():017.6f}".replace(".", "")
        return self.directory / f"{SEGMENT_PREFIX}{stamp}{SEGMENT_SUFFIX}"

    # --- ghi --------------------------------------------------------------
    def append(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
        path = self._active_segment()
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        os.chmod(path, 0o600)
        self._enforce_cap()

    def _enforce_cap(self) -> None:
        """Đầy thì bỏ segment CŨ NHẤT — và nói ra là đã bỏ."""
        while self.size_bytes() > self.max_bytes:
            segments = self.segments()
            if len(segments) <= 1:
                # Chỉ còn một segment: cắt bớt nửa đầu thay vì xoá sạch, để
                # không mất luôn những dòng vừa ghi.
                self._truncate_oldest_half(segments[0])
                break
            victim = segments[0]
            lost = sum(1 for _ in victim.open("r", encoding="utf-8", errors="replace"))
            victim.unlink()
            self.dropped += lost
            logger.warning("spool đầy: đã bỏ %d dòng cũ nhất (%s)", lost, victim.name)
            self._record_gap(lost)

    def _truncate_oldest_half(self, path: Path) -> None:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        keep = lines[len(lines) // 2:]
        lost = len(lines) - len(keep)
        path.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
        self.dropped += lost
        if lost:
            logger.warning("spool đầy: đã cắt %d dòng cũ nhất", lost)
            self._record_gap(lost)

    def _record_gap(self, lost: int) -> None:
        """Bản ghi tự tố cáo. Shield phải biết có một khoảng trống trong log,
        chứ không được nghĩ khoảng đó là "yên tĩnh"."""
        gap = {
            "ts": time.time(), "source": "probe", "kind": "probe_spool_overflow",
            "data": {"lines_lost": lost, "reason": "probe spool reached its size cap"},
        }
        line = json.dumps(gap, separators=(",", ":"), sort_keys=True) + "\n"
        with self._active_segment().open("a", encoding="utf-8") as handle:
            handle.write(line)

    # --- đọc --------------------------------------------------------------
    def read_batch(self, max_lines: int, max_bytes: int) -> tuple[list[dict], int]:
        """Đọc tối đa max_lines/max_bytes từ đầu hàng đợi. KHÔNG xoá gì —
        chỉ xoá sau khi server xác nhận đã nhận (xem `commit`)."""
        records: list[dict] = []
        consumed_bytes = 0
        for path in self.segments():
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    if len(records) >= max_lines or consumed_bytes >= max_bytes:
                        return records, consumed_bytes
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        records.append(json.loads(raw))
                    except ValueError:
                        # Dòng cụt do mất điện giữa lúc ghi — bỏ dòng đó thôi,
                        # không vứt cả file.
                        continue
                    consumed_bytes += len(raw) + 1
        return records, consumed_bytes

    def commit(self, count: int) -> int:
        """Xoá `count` dòng đầu tiên sau khi server đã xác nhận nhận được.

        Xoá-sau-khi-xác-nhận chứ không phải xoá-lúc-đọc: nếu mạng đứt giữa
        chừng, dòng đó vẫn còn và sẽ gửi lại. Thà gửi trùng còn hơn mất.
        """
        remaining = count
        removed = 0
        for path in self.segments():
            if remaining <= 0:
                break
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            if remaining >= len(lines):
                remaining -= len(lines)
                removed += len(lines)
                path.unlink()
                continue
            keep = lines[remaining:]
            removed += remaining
            remaining = 0
            path.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
            os.chmod(path, 0o600)
        return removed

    def pending_lines(self) -> int:
        total = 0
        for path in self.segments():
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                total += sum(1 for line in handle if line.strip())
        return total
