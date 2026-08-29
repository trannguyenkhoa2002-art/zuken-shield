"""Tarpit phòng thủ — nghe trên vài cổng "mồi" trên CHÍNH máy này; khi ai đó
TỰ kết nối tới (không phải Shield chủ động gửi gì ra ngoài), giữ kết nối
càng lâu càng tốt bằng cách nhỏ giọt vài byte rác cực chậm, không bao giờ
đóng trước — mục tiêu là làm lãng phí thời gian/tài nguyên công cụ quét/tấn
công của đối phương, giống kỹ thuật honeypot/tarpit cổ điển (LaBrea,
endlessh).

Ranh giới quan trọng, khác hẳn 1 công cụ tấn công: Shield KHÔNG BAO GIỜ tự
mở kết nối tới máy khác ở đây. Server chỉ `accept()` — hoàn toàn thụ động,
chỉ phản ứng lại kết nối đối phương tự khởi tạo tới cổng trên máy mình. Đây
là lý do tính năng này được giữ lại (khác với yêu cầu "gửi liên tục vào máy
đối phương" đã bị từ chối vì đó là tấn công chủ động).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time

logger = logging.getLogger("shield.tarpit")

# Nhỏ giọt 1 byte mỗi khoảng này — đủ để giữ TCP còn "sống" trong mắt client
# (không bị timeout do im lặng hoàn toàn) nhưng gần như không tốn băng
# thông/CPU của máy mình.
DRIP_INTERVAL_S = 8.0
DRIP_BYTE = b"\x00"

# Giới hạn để tự bảo vệ máy mình — không để 1 kẻ tấn công mở hàng nghìn kết
# nối làm cạn tài nguyên máy chủ nhà (biến phòng thủ thành tự-DoS chính mình).
MAX_CONCURRENT_CONNECTIONS = 100
# Trần theo TỪNG IP nguồn: nếu chỉ có trần tổng, 1 kẻ tấn công mở 100 kết nối
# là chiếm sạch slot, các IP khác không còn chỗ để bị "giữ chân" nữa. Trần
# theo IP đảm bảo tarpit vẫn bẫy được nhiều nguồn cùng lúc.
MAX_CONNECTIONS_PER_IP = 10
MAX_CONNECTION_DURATION_S = 30 * 60  # 30 phút — đủ lâu để câu giờ, không vô hạn

# Địa chỉ bind mặc định. 0.0.0.0 là đúng ý đồ cho máy trong LAN (mồi phải
# nhìn thấy được từ mạng nội bộ), nhưng trên máy có IP public thì nó cũng
# quảng cáo dịch vụ giả ra Internet. Đặt SHIELD_TARPIT_BIND để giới hạn về
# một địa chỉ cụ thể (ví dụ IP LAN của máy).
DEFAULT_BIND_HOST = "0.0.0.0"


def public_ipv4_addresses() -> list[str]:
    """IPv4 định tuyến công cộng đang gán trên máy (bỏ private/loopback/link-local)."""
    try:
        from shield.agent.collectors.discovery import subprocess_run

        out = subprocess_run(["ip", "-4", "-o", "addr", "show"])
    except Exception:
        logger.debug("Không liệt kê được địa chỉ IPv4 để cảnh báo tarpit", exc_info=True)
        return []
    found = []
    for raw in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out):
        addr = ipaddress.ip_address(raw)
        if addr.is_global:
            found.append(str(addr))
    return found


class TarpitManager:
    """Quản lý các `asyncio.Server` đang mở trên các cổng mồi, và danh sách
    kết nối đang bị giữ (để UI hiển thị)."""

    def __init__(self, bind_host: str | None = None) -> None:
        self.bind_host = bind_host or os.environ.get("SHIELD_TARPIT_BIND") or DEFAULT_BIND_HOST
        self._servers: dict[int, asyncio.AbstractServer] = {}
        self._connections: dict[str, dict] = {}  # conn_id -> {ip, port, since}
        self._on_new_connection = None  # callback(info: dict) -> None, gán từ ngoài

    @property
    def active_ports(self) -> list[int]:
        return sorted(self._servers)

    def list_connections(self) -> list[dict]:
        return sorted(self._connections.values(), key=lambda c: c["since"], reverse=True)

    async def start(self, ports: list[int]) -> tuple[list[int], list[tuple[int, str]]]:
        """Mở server trên các cổng chưa mở trong `ports`. Trả (cổng mở thành
        công, [(cổng, lý do lỗi)] cho cổng thất bại — ví dụ đã có dịch vụ
        thật đang dùng cổng đó, không phải lỗi để dừng cả tính năng).

        Khoá dict theo cổng THẬT SỰ đã bind (`getsockname()`), không phải
        giá trị `port` yêu cầu — với port thường (không phải 0) 2 giá trị
        này luôn giống nhau, chỉ khác khi test dùng port=0 (để OS tự cấp 1
        cổng trống), lúc đó khoá theo giá trị yêu cầu (luôn là 0) sẽ khiến
        nhiều server chồng lên đúng 1 key trong dict.
        """
        opened: list[int] = []
        failed: list[tuple[int, str]] = []
        if self.bind_host == "0.0.0.0" and ports:
            public = public_ipv4_addresses()
            if public:
                logger.warning(
                    "tarpit bind 0.0.0.0 nhưng máy đang có IP public (%s) — cổng mồi sẽ "
                    "lộ ra Internet. Đặt SHIELD_TARPIT_BIND=<IP LAN> để chỉ mở trong mạng nội bộ.",
                    ", ".join(public),
                )
        for port in ports:
            if port != 0 and port in self._servers:
                opened.append(port)
                continue
            try:
                server = await asyncio.start_server(self._handle_client, host=self.bind_host, port=port)
            except OSError as e:
                failed.append((port, str(e)))
                continue
            real_port = server.sockets[0].getsockname()[1]
            self._servers[real_port] = server
            opened.append(real_port)
            logger.info("tarpit: đang nghe cổng mồi %d", real_port)
        return opened, failed

    async def stop_all(self) -> None:
        for port, server in list(self._servers.items()):
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
            logger.info("tarpit: đã đóng cổng mồi %d", port)
        self._servers.clear()
        self._connections.clear()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._connections) >= MAX_CONCURRENT_CONNECTIONS:
            writer.close()
            return

        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "?"
        src_port = peer[1] if peer else 0

        # Trần theo IP nguồn — 1 IP đã giữ đủ MAX_CONNECTIONS_PER_IP thì đóng
        # ngay kết nối mới của chính nó, nhường slot cho các nguồn khác.
        if sum(1 for c in self._connections.values() if c["ip"] == src_ip) >= MAX_CONNECTIONS_PER_IP:
            writer.close()
            return
        local_port = writer.get_extra_info("sockname")
        local_port = local_port[1] if local_port else 0
        conn_id = f"{src_ip}:{src_port}-{time.time()}"
        info = {
            "conn_id": conn_id, "ip": src_ip, "src_port": src_port,
            "port": local_port, "since": time.time(), "bytes_sent": 0,
        }
        self._connections[conn_id] = info
        logger.warning(
            "tarpit: %s kết nối tới cổng mồi %d — bắt đầu giữ kết nối", src_ip, local_port
        )
        if self._on_new_connection:
            try:
                self._on_new_connection(dict(info))
            except Exception:
                logger.exception("Lỗi callback tarpit._on_new_connection")

        deadline = time.time() + MAX_CONNECTION_DURATION_S
        try:
            while time.time() < deadline:
                writer.write(DRIP_BYTE)
                await writer.drain()
                info["bytes_sent"] += 1
                await asyncio.sleep(DRIP_INTERVAL_S)
        except (ConnectionError, OSError):
            pass  # đối phương tự ngắt — kết thúc bình thường, không phải lỗi
        finally:
            self._connections.pop(conn_id, None)
            writer.close()
            duration = time.time() - info["since"]
            logger.info(
                "tarpit: %s ngắt khỏi cổng mồi %d sau %.0fs (%d byte)",
                src_ip, local_port, duration, info["bytes_sent"],
            )


def parse_port_list(raw: str) -> list[int]:
    """Parse chuỗi cổng người dùng nhập kiểu "2222, 4444,8081" -> [2222,4444,8081].
    Bỏ qua token rỗng/không phải số/ngoài phạm vi cổng hợp lệ, không ném lỗi
    (input người dùng gõ tay, dễ lệch định dạng)."""
    ports: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token.isdigit():
            continue
        port = int(token)
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


DEFAULT_TARPIT_PORTS = [2222, 4444, 8081, 31337]
