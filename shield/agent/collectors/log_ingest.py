"""Nhận log từ Shield Probe (KE-HOACH-SHIELD-1.1.md mục A1/A3).

Đây là đường vào HẠNG NHẤT: probe có certificate, nên mỗi dòng đến đây đều có
danh tính mật mã và mang `trust="authenticated"` — khác hẳn syslog thô ở
`syslog_server.py`.

Ba thứ quyết định độ an toàn của cửa này:

1. mTLS bắt buộc — `verify_mode=CERT_REQUIRED`, dùng lại
   `fleet_server_context()` đã có trong security/fleet.py.
2. Fingerprint phải nằm trong `fleet_endpoints` với role `probe`. Có
   certificate hợp lệ chưa đủ, còn phải được ghi danh.
3. Rate-limit theo từng probe. Một probe hỏng (hoặc bị chiếm) không được làm
   nghẹt event_bus — trần queue là 4096 dòng, xem bus.py.

Kênh này MỘT CHIỀU. Server không gửi lệnh nào xuống probe.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
import time

from shield.agent.bus import Bus
from shield.agent.switch import allows
from shield.common.models import Event
from shield.security.trust import AUTHENTICATED

logger = logging.getLogger("shield.log_ingest")

PROBE_ROLE = "probe"
MAX_BATCH_BYTES = 1024 * 1024
MAX_RECORDS_PER_BATCH = 1000
DEFAULT_RATE_PER_PROBE = 500  # dòng/giây
MAX_MESSAGE_CHARS = 2000

# Kind mà probe được phép gửi. Allowlist chứ không phải blocklist: một probe
# bị chiếm quyền không được tự chọn kind để kích hoạt detector tuỳ ý.
ALLOWED_KINDS = frozenset({
    "log_line", "ssh_auth_failure", "ssh_auth_success", "sudo_failure",
    "usb_device_added", "process_exec", "process_started", "listener_opened",
    "service_changed", "probe_spool_overflow",
})
# Chỉ liệt kê những source probe THẬT SỰ sinh ra: một mục thừa trong allowlist
# là một đường vào không ai kiểm. Cả ba đều có hàm sinh tương ứng trong
# probe/reader.py — có test khẳng định điều đó (test_probe.py).
ALLOWED_SOURCES = frozenset({"probe", "probe.journal", "probe.file", "probe.audit"})


class ProbeRateLimiter:
    def __init__(self, rate_per_s: int = DEFAULT_RATE_PER_PROBE) -> None:
        self.rate_per_s = max(1, int(rate_per_s))
        self._buckets: dict[str, tuple[float, float]] = {}

    def take(self, probe_id: str, count: int, at: float | None = None) -> int:
        """Trả về số dòng ĐƯỢC PHÉP nhận. Phần vượt bị bỏ và đếm riêng."""
        at = time.monotonic() if at is None else at
        tokens, last = self._buckets.get(probe_id, (float(self.rate_per_s), at))
        tokens = min(float(self.rate_per_s), tokens + (at - last) * self.rate_per_s)
        granted = int(min(count, tokens))
        self._buckets[probe_id] = (tokens - granted, at)
        return granted


def normalize_record(raw: dict, probe_id: str, remote_addr: str) -> Event | None:
    """Chuẩn hoá và kiểm tra một bản ghi từ probe.

    Probe là phần mềm chạy trên máy KHÁC. Dữ liệu nó gửi là dữ liệu không tin
    được về mặt cấu trúc, kể cả khi danh tính của nó đã xác thực — cùng lý do
    `handle_command` trong agent validate lại mọi thứ UI gửi lên.
    """
    if not isinstance(raw, dict):
        return None
    source = str(raw.get("source", ""))
    kind = str(raw.get("kind", ""))
    if source not in ALLOWED_SOURCES or kind not in ALLOWED_KINDS:
        return None
    data = raw.get("data")
    if not isinstance(data, dict):
        return None

    try:
        ts = float(raw.get("ts", 0))
    except (TypeError, ValueError):
        return None
    # Không cho probe tự khai thời gian tương lai: nếu cho, một probe bị chiếm
    # sẽ đẩy được sự kiện lên đầu mọi timeline điều tra.
    now_ts = time.time()
    if not (now_ts - 86400 * 7) <= ts <= (now_ts + 300):
        ts = now_ts

    clean = {}
    for key, value in list(data.items())[:40]:
        key = str(key)[:48]
        if isinstance(value, str):
            clean[key] = value[:MAX_MESSAGE_CHARS]
        elif isinstance(value, (int, float, bool)) or value is None:
            clean[key] = value
    # origin/trust do SERVER gắn, không bao giờ lấy từ payload — nếu không,
    # probe tự khai được mình là "local" và vượt qua mọi ranh giới tin cậy.
    clean["origin"] = f"probe:{probe_id}"
    clean["trust"] = AUTHENTICATED
    clean["probe_id"] = probe_id
    clean["probe_addr"] = remote_addr
    return Event(ts=ts, source=source, kind=kind, data=clean)


class LogIngestServer:
    """Server mTLS nhận batch NDJSON từ probe."""

    def __init__(
        self, event_bus: Bus, registry, store, context: ssl.SSLContext,
        host: str = "0.0.0.0", port: int = 9443,  # noqa: S104 - probe ở máy khác
        rate_per_s: int = DEFAULT_RATE_PER_PROBE,
    ) -> None:
        if context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("log ingest requires mutual TLS")
        self.event_bus = event_bus
        self.registry = registry
        self.store = store
        self.context = context
        self.host, self.port = host, int(port)
        self.limiter = ProbeRateLimiter(rate_per_s)
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle, self.host, self.port, ssl=self.context, limit=MAX_BATCH_BYTES,
        )
        logger.warning("log ingest: đang nghe %s:%d (mTLS TLSv1.3)", self.host, self.port)
        return self.server

    def _authorize(self, fingerprint: str) -> dict | None:
        endpoint = self.registry.store.get_endpoint_by_fingerprint(fingerprint)
        if not endpoint or endpoint.get("role") != PROBE_ROLE:
            return None
        return endpoint

    async def _handle(self, reader, writer) -> None:
        remote = writer.get_extra_info("peername")
        remote_addr = remote[0] if remote else ""
        response = {"ok": False, "accepted": 0, "message": "rejected"}
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            if not certificate:
                raise PermissionError("client certificate required")
            fingerprint = hashlib.sha256(certificate).hexdigest()
            endpoint = self._authorize(fingerprint)
            if endpoint is None:
                raise PermissionError("probe is not enrolled")

            line = await asyncio.wait_for(reader.readline(), 30)
            if not line or len(line) > MAX_BATCH_BYTES:
                raise ValueError("invalid batch size")
            response = await self._ingest(json.loads(line), endpoint, remote_addr)
        except (PermissionError, ValueError, TypeError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("log ingest từ %s bị từ chối: %s", remote_addr, exc)
            response = {"ok": False, "accepted": 0, "message": f"{type(exc).__name__}: {exc}"}
        finally:
            try:
                writer.write((json.dumps(response) + "\n").encode())
                await writer.drain()
            except OSError:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _ingest(self, message: dict, endpoint: dict, remote_addr: str) -> dict:
        if not isinstance(message, dict):
            raise ValueError("invalid batch envelope")
        records = message.get("records")
        if not isinstance(records, list):
            raise ValueError("invalid batch envelope")
        if len(records) > MAX_RECORDS_PER_BATCH:
            raise ValueError("batch too large")

        # Định danh probe LUÔN lấy từ certificate, không bao giờ từ payload:
        # probe_id trong JSON là thứ người gửi tự khai.
        probe_id = str(endpoint["endpoint_id"])
        display_name = str(endpoint.get("display_name", ""))

        if not allows("passive"):
            return {"ok": True, "accepted": 0, "message": "monitoring paused"}

        granted = self.limiter.take(probe_id, len(records))
        dropped = len(records) - granted
        accepted = 0
        latest_ts = 0.0
        for raw in records[:granted]:
            event = normalize_record(raw, probe_id, remote_addr)
            if event is None:
                continue
            await self.event_bus.publish(event)
            accepted += 1
            latest_ts = max(latest_ts, event.ts)

        if self.store is not None:
            self.store.record_probe_health(
                probe_id, display_name=display_name, remote_addr=remote_addr,
                lines=accepted, dropped=dropped, last_event_ts=latest_ts,
                error="rate limited" if dropped else "",
            )
        if dropped:
            logger.warning("probe %s vượt tốc độ: bỏ %d dòng", display_name or probe_id, dropped)
        return {"ok": True, "accepted": accepted, "dropped": dropped}

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
