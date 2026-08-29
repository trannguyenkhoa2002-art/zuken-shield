"""Nhận quan sát gói tin từ helper TÁCH RIÊNG, biến thành Event chuẩn tắc.

Lõi Shield không import scapy. Việc bóc gói nằm ở `shield-packet-collector`,
một chương trình riêng, một tiến trình riêng, một gói cài riêng — xem
`packet_helper/`. Ranh giới đó tồn tại để giấy phép của lõi rõ ràng và kiểm
được, và nó cũng cho một lợi ích an toàn thật: một bộ bóc gói bị gói dị dạng
làm sập không kéo theo agent.

Helper là ĐẦU VÀO KHÔNG TIN CẬY. Nó chạy bằng root và đọc gói tin từ mạng —
đúng thứ kẻ tấn công điều khiển được. Nên mọi bản tin đi qua bộ kiểm đóng ở
`packet_protocol` trước khi trở thành Event, và một bản tin sai bị BỎ
kèm một con số đếm được, không phải một ngoại lệ nuốt lặng.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time

from shield.agent.collectors.packet_protocol import (MAX_LINE_BYTES, OBSERVATIONS,
                                                     SCHEMA_VERSION, SOCKET_PATH,
                                                     clean_payload)
from shield.agent.bus import Bus
from shield.common.models import Event

logger = logging.getLogger("shield.packet_ingest")

RECONNECT_DELAY_S = 5.0
# Trần nhận. Helper lụt gói không được làm vòng lặp sự kiện của agent đói.
MAX_EVENTS_PER_S = 2000


class PacketIngestHealth:
    """Đếm được, để tab Sức khoẻ nói thật thay vì đoán."""

    def __init__(self) -> None:
        self.connected = False
        self.accepted = 0
        self.rejected = 0
        self.throttled = 0
        self.connects = 0
        self.last_event_ts = 0.0
        self.last_error = ""

    def to_dict(self) -> dict:
        return {"connected": self.connected, "accepted": self.accepted,
                "rejected": self.rejected, "throttled": self.throttled,
                "connects": self.connects, "last_event_ts": self.last_event_ts,
                "last_error": self.last_error[:200]}


def parse_line(raw: bytes) -> tuple[str, str, dict, float] | None:
    """Một dòng NDJSON -> `(source, kind, data, ts)` hoặc `None`.

    THUẦN, nên mọi cách bản tin có thể hỏng đều test được mà không cần socket.
    """
    if not raw or len(raw) > MAX_LINE_BYTES:
        return None
    try:
        message = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(message, dict):
        return None
    if message.get("version") != SCHEMA_VERSION:
        return None
    observation = message.get("event_type")
    if observation not in OBSERVATIONS:
        return None
    source, kind = OBSERVATIONS[observation]
    if message.get("collector") != source:
        return None
    timestamp = message.get("timestamp")
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
        return None
    now = time.time()
    # Mốc thời gian phải HỢP LÝ: helper không được viết lại lịch sử, cũng không
    # được đặt sự kiện vào tương lai để lách cửa sổ tương quan.
    if not (now - 3600) <= float(timestamp) <= (now + 60):
        return None
    payload = clean_payload(message.get("payload"))
    if payload is None:
        return None
    return source, kind, payload, float(timestamp)


async def ingest_loop(event_bus: Bus, *, socket_path: str = SOCKET_PATH,
                      health: PacketIngestHealth | None = None,
                      store=None, retry: bool = True) -> None:
    """Kết nối helper, đọc quan sát, phát Event. Helper vắng mặt là BÌNH THƯỜNG."""
    health = health or PacketIngestHealth()
    window_start, window_count = time.monotonic(), 0

    while True:
        if not os.path.exists(socket_path):
            health.connected = False
            health.last_error = "helper chưa chạy"
            if store is not None:
                with contextlib.suppress(Exception):
                    store.set_collector_health(
                        "packet_ingest", "helper", False,
                        "shield-packet-collector chưa cài hoặc chưa chạy")
            if not retry:
                return
            await asyncio.sleep(RECONNECT_DELAY_S)
            continue
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
        except (OSError, asyncio.CancelledError) as exc:
            health.connected = False
            health.last_error = f"{type(exc).__name__}: {exc}"
            if not retry:
                return
            await asyncio.sleep(RECONNECT_DELAY_S)
            continue

        health.connected = True
        health.connects += 1
        logger.info("Nối được helper bắt gói tại %s", socket_path)
        if store is not None:
            with contextlib.suppress(Exception):
                store.set_collector_health("packet_ingest", "helper", True, "")
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break                       # helper đóng kết nối hoặc chết
                now = time.monotonic()
                if now - window_start >= 1.0:
                    window_start, window_count = now, 0
                window_count += 1
                if window_count > MAX_EVENTS_PER_S:
                    health.throttled += 1
                    continue
                parsed = parse_line(raw.strip())
                if parsed is None:
                    health.rejected += 1
                    continue
                source, kind, data, ts = parsed
                health.accepted += 1
                health.last_event_ts = ts
                await event_bus.publish(
                    Event(ts=ts, source=source, kind=kind, data=data))
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError) as exc:
            health.last_error = f"{type(exc).__name__}: {exc}"
        finally:
            health.connected = False
            with contextlib.suppress(Exception):
                writer.close()
        if not retry:
            return
        await asyncio.sleep(RECONNECT_DELAY_S)


def collector_status(socket_path: str = SOCKET_PATH,
                     health: PacketIngestHealth | None = None) -> dict:
    """Trạng thái CÓ CẤU TRÚC của thành phần tuỳ chọn này.

    Dò bằng đường dẫn CỐ ĐỊNH, không quét PATH: một helper tìm được bằng cách
    dò là một helper giả mạo được.
    """
    installed = os.path.exists("/opt/shield/.venv/bin/shield-packet-collector") or \
        os.path.exists("/usr/bin/shield-packet-collector")
    running = os.path.exists(socket_path)
    state = health.to_dict() if health else {}
    return {"installed": installed, "running": running,
            "available": bool(state.get("connected")),
            "version": state.get("version", ""),
            "last_event": state.get("last_event_ts", 0.0),
            "health": state}
