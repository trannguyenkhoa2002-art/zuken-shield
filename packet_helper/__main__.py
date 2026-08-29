"""Tiến trình helper: bắt gói, phát quan sát NDJSON qua Unix socket.

Chạy độc lập với `shield-agent`. Lõi kết nối tới đây; helper không bao giờ kết
nối ngược, không nhận lệnh, và không có đường nào chạm vào cơ sở dữ liệu hay
tầng phản ứng của Shield.

Helper chết thì lõi mất đúng phần quan sát gói tin. Nó KHÔNG kéo agent xuống.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import socket
import time

from packet_helper import __version__
from packet_helper.protocol import (MAX_LINE_BYTES, OBSERVATIONS, SOCKET_PATH,
                                    clean_payload, envelope)
from packet_helper.sniffers import (BPF_ARP, BPF_CONN, BPF_DNS, from_arp_packet,
                                    from_dns_packet, from_tcp_packet)

logger = logging.getLogger("shield.packet_helper")

# Trần hàng đợi. Một trận lụt gói tin không được biến helper thành nơi ngốn RAM:
# đầy thì BỎ gói mới nhất và đếm, chứ không phình ra vô hạn.
MAX_QUEUE = 2000


def local_addresses() -> set[str]:
    """Địa chỉ của chính máy này, đọc từ hệ điều hành. Không phụ thuộc scapy."""
    found: set[str] = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))     # địa chỉ tài liệu, không gửi gì
            found.add(probe.getsockname()[0])
    except OSError:
        pass
    return found


class Publisher:
    """Giữ danh sách client đang nghe và phát quan sát cho họ."""

    def __init__(self) -> None:
        self._clients: set[asyncio.Queue] = set()
        self.dropped = 0
        self.published = 0

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE)
        self._clients.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._clients.discard(queue)

    def publish(self, observation: str, payload: dict) -> None:
        if observation not in OBSERVATIONS:
            return
        safe = clean_payload(payload)
        if safe is None:
            return
        line = json.dumps(envelope(observation, safe, time.time()),
                          separators=(",", ":"))
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            return
        self.published += 1
        for queue in self._clients:
            try:
                queue.put_nowait(line)
            except asyncio.QueueFull:
                self.dropped += 1


async def _serve_client(reader, writer, publisher: Publisher) -> None:
    queue = publisher.subscribe()
    try:
        while True:
            line = await queue.get()
            writer.write(line.encode("utf-8") + b"\n")
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        publisher.unsubscribe(queue)
        with contextlib.suppress(Exception):
            writer.close()


def _start_sniffer(loop, publisher: Publisher, bpf: str, interface, handler) -> object:
    from scapy.all import AsyncSniffer

    def on_packet(pkt) -> None:
        try:
            result = handler(pkt)
        except Exception:                       # noqa: BLE001 — gói dị dạng là bình thường
            return
        if result:
            loop.call_soon_threadsafe(publisher.publish, result[0], result[1])

    sniffer = AsyncSniffer(iface=interface, filter=bpf, prn=on_packet, store=False)
    sniffer.start()
    return sniffer


async def main_async(args) -> int:
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        logger.error("Chưa cài scapy — helper bắt gói không chạy được.")
        return 1

    publisher = Publisher()
    loop = asyncio.get_running_loop()
    mine = local_addresses()
    logger.info("Địa chỉ cục bộ: %s", sorted(mine))

    sniffers = []
    if not args.no_arp:
        sniffers.append(_start_sniffer(loop, publisher, BPF_ARP, args.interface,
                                       from_arp_packet))
    if not args.no_conn:
        sniffers.append(_start_sniffer(loop, publisher, BPF_CONN, args.interface,
                                       lambda pkt: from_tcp_packet(pkt, mine)))
    if not args.no_dns:
        sniffers.append(_start_sniffer(loop, publisher, BPF_DNS, args.interface,
                                       from_dns_packet))

    path = args.socket
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    server = await asyncio.start_unix_server(
        lambda r, w: _serve_client(r, w, publisher), path=path)
    os.chmod(path, 0o660)
    logger.info("Shield packet collector %s lắng nghe tại %s (interface=%s)",
                __version__, path, args.interface or "(mặc định)")

    try:
        async with server:
            await server.serve_forever()
    finally:
        for sniffer in sniffers:
            with contextlib.suppress(Exception):
                sniffer.stop()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="shield-packet-collector",
        description="Bắt gói tin cho Shield. Thành phần TUỲ CHỌN, tách riêng.")
    parser.add_argument("--socket", default=SOCKET_PATH)
    parser.add_argument("--interface", default=None)
    parser.add_argument("--no-arp", action="store_true")
    parser.add_argument("--no-conn", action="store_true")
    parser.add_argument("--no-dns", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
