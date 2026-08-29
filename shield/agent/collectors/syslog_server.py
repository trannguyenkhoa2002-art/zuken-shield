"""Nhận syslog từ thiết bị không cài được agent — router, switch, AP, camera IP.

Đây là đường vào HẠNG HAI, có chủ ý (KE-HOACH-SHIELD-1.1.md mục A2). Giao
thức syslog không có xác thực: bất kỳ ai trong LAN cũng gửi được một gói UDP
khai mình là router, và hostname bên trong gói là do người gửi tự khai. Vì
vậy mọi event ra khỏi đây đều mang `trust="unauthenticated"`, và
`security/trust.py` chặn chúng khỏi forensic ledger, khỏi mức critical, và
khỏi việc huấn luyện baseline.

Bốn ranh giới cứng, tất cả đều fail closed:

1. Mặc định bind 127.0.0.1 — phải sửa cấu hình mới mở ra LAN (cùng nguyên
   tắc đã áp cho tarpit.py).
2. Allowlist RỖNG = không nhận gì. Không có chế độ "nhận tất cả".
3. Rate-limit theo từng IP nguồn — một thiết bị hỏng phun log không được làm
   nghẹt event_bus (trần 4096 dòng, xem bus.py).
4. Bỏ mọi datagram quá cỡ trước khi parse.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
from dataclasses import dataclass, field

from shield.agent.bus import Bus
from shield.agent.switch import allows
from shield.common.models import Event, now
from shield.security.trust import UNAUTHENTICATED

logger = logging.getLogger("shield.syslog")

# Cổng cao (>1024) để không cần thêm quyền. Cổng 514 chuẩn vẫn đặt được qua
# SHIELD_SYSLOG_PORT nếu người dùng thật sự cần.
DEFAULT_SYSLOG_PORT = 5514
DEFAULT_BIND_HOST = "127.0.0.1"
MAX_DATAGRAM_BYTES = 8 * 1024
DEFAULT_RATE_PER_SOURCE = 100  # dòng/giây
MAX_TRACKED_SOURCES = 4096

FACILITIES = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp",
    "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0",
    "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)
SEVERITIES = (
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
)

# RFC3164:  <34>Oct 11 22:14:15 mymachine su: 'su root' failed
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[^\s]+)\s+"
    r"(?P<message>.*)$",
    re.DOTALL,
)
# RFC5424:  <34>1 2003-10-11T22:14:15.003Z host su - ID47 - message
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2})\s+"
    r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)
_TAG = re.compile(r"^(?P<tag>[\w\-./]{1,48})(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<body>.*)$", re.DOTALL)


def parse_priority(raw: str) -> tuple[str, str]:
    try:
        value = int(raw)
    except ValueError:
        return "unknown", "unknown"
    if not 0 <= value <= 191:
        return "unknown", "unknown"
    facility, severity = divmod(value, 8)
    return (
        FACILITIES[facility] if facility < len(FACILITIES) else "unknown",
        SEVERITIES[severity] if severity < len(SEVERITIES) else "unknown",
    )


def parse_syslog(payload: str) -> dict | None:
    """Trả về các trường đã tách, hoặc None nếu không phải syslog hợp lệ.

    KHÔNG cố đoán bừa: một dòng không parse được thì bỏ, chứ không nhét cả
    chuỗi thô vào `message` — làm vậy là mở đường cho người gửi tự chọn nội
    dung của mọi trường.
    """
    payload = payload.strip("\x00").strip()
    if not payload or not payload.startswith("<"):
        return None

    match = _RFC5424.match(payload)
    if match:
        facility, severity = parse_priority(match.group("pri"))
        return {
            "format": "rfc5424", "facility": facility, "severity": severity,
            "reported_hostname": match.group("hostname")[:255],
            "app": match.group("app")[:48],
            "procid": match.group("procid")[:32],
            "msgid": match.group("msgid")[:32],
            "message": match.group("rest")[:2000],
            "reported_timestamp": match.group("timestamp")[:64],
        }

    match = _RFC3164.match(payload)
    if match:
        facility, severity = parse_priority(match.group("pri"))
        parsed = {
            "format": "rfc3164", "facility": facility, "severity": severity,
            "reported_hostname": match.group("hostname")[:255],
            "app": "", "procid": "", "msgid": "",
            "message": match.group("message")[:2000],
            "reported_timestamp": match.group("timestamp")[:64],
        }
        tag = _TAG.match(parsed["message"])
        if tag:
            parsed["app"] = tag.group("tag")[:48]
            parsed["procid"] = tag.group("pid") or ""
            parsed["message"] = tag.group("body")[:2000]
        return parsed
    return None


def allowed_sources(raw: str | None = None) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Đọc allowlist từ SHIELD_SYSLOG_ALLOWED_SOURCES (IP hoặc CIDR, cách nhau
    bằng dấu phẩy). Rỗng = không nhận gì. Không có chế độ nhận tất cả."""
    raw = os.environ.get("SHIELD_SYSLOG_ALLOWED_SOURCES", "") if raw is None else raw
    networks = []
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("syslog: bỏ qua mục allowlist không hợp lệ: %r", item)
    return tuple(networks)


def source_is_allowed(address: str, networks) -> bool:
    if not networks:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in networks)


@dataclass
class RateLimiter:
    """Thùng token đơn giản, một thùng cho mỗi IP nguồn.

    Có trần số IP theo dõi: nếu không, kẻ tấn công giả mạo IP nguồn ngẫu
    nhiên sẽ làm chính bộ đếm này ngốn hết bộ nhớ.
    """

    rate_per_s: int = DEFAULT_RATE_PER_SOURCE
    max_sources: int = MAX_TRACKED_SOURCES
    _buckets: dict = field(default_factory=dict)

    def allow(self, source: str, at: float | None = None) -> bool:
        at = time.monotonic() if at is None else at
        tokens, last = self._buckets.get(source, (float(self.rate_per_s), at))
        tokens = min(float(self.rate_per_s), tokens + (at - last) * self.rate_per_s)
        if tokens < 1.0:
            self._buckets[source] = (tokens, at)
            return False
        if source not in self._buckets and len(self._buckets) >= self.max_sources:
            # Hết chỗ theo dõi -> từ chối, không im lặng cho qua.
            return False
        self._buckets[source] = (tokens - 1.0, at)
        return True


class SyslogCollector:
    """Nhận syslog UDP + TCP rồi đẩy vào event bus dưới dạng Event."""

    def __init__(
        self, event_bus: Bus, *, host: str | None = None, port: int | None = None,
        allowlist: str | None = None, rate_per_s: int | None = None, store=None,
    ) -> None:
        self.event_bus = event_bus
        self.host = host or os.environ.get("SHIELD_SYSLOG_BIND", DEFAULT_BIND_HOST)
        self.port = int(port or os.environ.get("SHIELD_SYSLOG_PORT", DEFAULT_SYSLOG_PORT))
        self.networks = allowed_sources(allowlist)
        self.limiter = RateLimiter(int(
            rate_per_s or os.environ.get("SHIELD_SYSLOG_RATE_PER_SOURCE", DEFAULT_RATE_PER_SOURCE)
        ))
        self.store = store
        self.accepted = 0
        self.rejected_source = 0
        self.rejected_rate = 0
        self.rejected_parse = 0
        self.rejected_size = 0
        self._udp = None
        self._tcp = None

    # --- xử lý một dòng ---------------------------------------------------
    async def handle_payload(self, payload: bytes, address: str) -> bool:
        # Công tắc kiểm ở ĐÂY chứ không ở tầng transport: trước đây chỉ nhánh
        # UDP kiểm, nên "Dừng toàn bộ giám sát" vẫn để lọt syslog gửi qua TCP.
        if not allows("passive"):
            return False
        if len(payload) > MAX_DATAGRAM_BYTES:
            self.rejected_size += 1
            return False
        if not source_is_allowed(address, self.networks):
            self.rejected_source += 1
            return False
        if not self.limiter.allow(address):
            self.rejected_rate += 1
            return False
        parsed = parse_syslog(payload.decode("utf-8", "replace"))
        if parsed is None:
            self.rejected_parse += 1
            return False

        # `subject` LUÔN là IP nguồn, không bao giờ là hostname trong gói:
        # hostname là thứ người gửi tự khai, dùng nó làm danh tính nghĩa là
        # cho phép bất kỳ ai mạo danh bất kỳ thiết bị nào.
        await self.event_bus.publish(Event(
            ts=now(), source="syslog", kind="syslog_message",
            data={
                **parsed,
                "source_ip": address,
                "origin": f"syslog:{address}",
                "trust": UNAUTHENTICATED,
            },
        ))
        self.accepted += 1
        return True

    def kernel_dropped(self) -> int:
        """Số datagram nhân đã bỏ vì bộ đệm nhận đầy.

        Bộ đếm của chính collector chỉ đếm cái nó ĐỌC ĐƯỢC. Khi nguồn bắn nhanh
        hơn vòng lặp đọc, nhân vứt gói ngay ở socket và collector không hề hay
        biết — mọi bộ đếm vẫn đẹp trong khi log đang mất. Với một sản phẩm giám
        sát thì mất log âm thầm là kiểu hỏng tệ nhất, nên số này phải hiện ra.

        Đọc từ /proc/net/udp (Linux). Không đọc được thì trả -1 chứ không trả 0:
        "không biết" và "không mất gói nào" là hai chuyện khác nhau.
        """
        try:
            wanted = f"{self.port:04X}"
            with open("/proc/net/udp", encoding="ascii") as handle:
                next(handle, None)
                for line in handle:
                    fields = line.split()
                    if len(fields) < 13:
                        continue
                    if fields[1].rsplit(":", 1)[-1] == wanted:
                        return int(fields[12])
        except (OSError, ValueError, StopIteration):
            return -1
        return 0

    def stats(self) -> dict:
        return {
            "kernel_dropped": self.kernel_dropped(),
            "accepted": self.accepted,
            "rejected_source": self.rejected_source,
            "rejected_rate": self.rejected_rate,
            "rejected_parse": self.rejected_parse,
            "rejected_size": self.rejected_size,
            "allowlist_entries": len(self.networks),
            "listening": bool(self._udp or self._tcp),
        }

    # --- vòng đời server --------------------------------------------------
    async def start(self) -> bool:
        if not self.networks:
            logger.info(
                "syslog: không bật — SHIELD_SYSLOG_ALLOWED_SOURCES đang rỗng "
                "(fail closed, không có chế độ nhận tất cả)"
            )
            return False
        loop = asyncio.get_running_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self), local_addr=(self.host, self.port),
        )
        self._udp = transport
        self._tcp = await asyncio.start_server(
            self._handle_tcp, self.host, self.port, limit=MAX_DATAGRAM_BYTES,
        )
        logger.warning(
            "syslog: đang nghe %s:%d (UDP+TCP), allowlist %d mục — mọi dòng nhận "
            "về đều là unauthenticated",
            self.host, self.port, len(self.networks),
        )
        return True

    async def _handle_tcp(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        address = peer[0] if peer else ""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                await self.handle_payload(line, address)
        except (OSError, asyncio.LimitOverrunError, ValueError):
            self.rejected_size += 1
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def stop(self) -> None:
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        if self._tcp is not None:
            self._tcp.close()
            await self._tcp.wait_closed()
            self._tcp = None

    async def run(self) -> None:
        """Vòng đời dùng cho CollectorSupervisor."""
        if not await self.start():
            # Không bật thì ngủ yên, không quay vòng tốn CPU và không để
            # supervisor tưởng collector này crash liên tục.
            while True:
                await asyncio.sleep(3600)
        try:
            while True:
                await asyncio.sleep(60)
                if self.store is not None:
                    stats = self.stats()
                    self.store.set_collector_health(
                        "syslog_server", f"{self.host}:{self.port}", True,
                        f"nhận {stats['accepted']}, từ chối nguồn "
                        f"{stats['rejected_source']}, quá tốc độ {stats['rejected_rate']}",
                    )
        finally:
            await self.stop()


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: SyslogCollector) -> None:
        self.collector = collector

    def datagram_received(self, data: bytes, addr) -> None:
        asyncio.create_task(self.collector.handle_payload(data, addr[0]))
