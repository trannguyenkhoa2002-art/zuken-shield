"""Đọc `journalctl -f -o json`, bắt sshd/sudo/USB/promiscuous mode
(KE-HOACH-SHIELD.md mục 2.4).

Chỉ mô tả sự thật đã lọc theo SYSLOG_IDENTIFIER/nội dung — quyết định có
đáng báo không là việc của detector (local_log.py). "Đã lọc" vì tab Log máy
chỉ hiện các dòng match, không phải toàn bộ journal (sẽ ngập UI).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re

from shield.agent.bus import Bus
from shield.common.models import Event, now
from shield.agent.collectors.auditd import parse_audit_message

logger = logging.getLogger("shield.journal")

_SSH_FAILED_RE = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
# Đăng nhập THÀNH CÔNG. Trước 2.0 Shield chỉ ghi lần thất bại, nên timeline
# điều tra không bao giờ có mắt xích "ai đã vào được máy" — mà đó chính là câu
# hỏi đầu tiên người ta đặt ra khi mở một sự việc.
# Ví dụ: "Accepted publickey for khoa from 192.168.1.20 port 51234 ssh2"
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted (\S+) for (\S+) from (\d+\.\d+\.\d+\.\d+)(?: port (\d+))?"
)
_PROMISC_RE = re.compile(r"device (\S+) entered promiscuous mode")
_SUDO_USER_RE = re.compile(r"^(\S+)\s*:")

# Chờ bao lâu trước khi khởi động lại journalctl nếu nó chết bất ngờ (journald
# restart, lỗi thoáng qua...). Trước đây journal_loop chỉ return khi readline()
# ra rỗng — cả 4 rule log máy (SSH bruteforce, sudo fail, USB, promiscuous)
# im lặng dừng vĩnh viễn cho tới khi restart cả agent, không có cảnh báo rõ.
RESTART_DELAY_S = 5


async def journal_loop(event_bus: Bus) -> None:
    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "journalctl", "-f", "-o", "json", "-n", "0",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error("Không tìm thấy 'journalctl' trong PATH — journal collector dừng hẳn.")
            return  # lỗi cấu hình máy, không phải sự cố thoáng qua — retry vô ích

        logger.info("journal collector bắt đầu (journalctl -f)")
        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    logger.warning(
                        "journalctl -f kết thúc bất ngờ — khởi động lại sau %ds", RESTART_DELAY_S
                    )
                    break
                await _handle_line(event_bus, line)
        finally:
            if proc.returncode is None:
                proc.terminate()
                await proc.wait()
        await asyncio.sleep(RESTART_DELAY_S)


async def _handle_line(event_bus: Bus, raw: bytes) -> None:
    try:
        entry = json.loads(raw.decode(errors="ignore"))
    except json.JSONDecodeError:
        return

    identifier = entry.get("SYSLOG_IDENTIFIER", "")
    message = entry.get("MESSAGE", "")
    if not isinstance(message, str):  # journald có thể trả list byte-array cho message nhị phân
        return

    if identifier in {"audit", "auditd"} or entry.get("_TRANSPORT") == "audit":
        event = parse_audit_message(message)
        if event is not None:
            await event_bus.publish(event)
        return

    if identifier == "sshd" and "Accepted " in message:
        m = _SSH_ACCEPTED_RE.search(message)
        if m:
            method, user, src_ip, port = m.groups()
            await event_bus.publish(
                Event(
                    ts=now(),
                    source="journal",
                    kind="ssh_login",
                    data={"user": user, "src_ip": src_ip, "method": method,
                          "src_port": int(port) if port else 0, "message": message},
                )
            )
        return

    if identifier == "sshd" and "Failed password" in message:
        m = _SSH_FAILED_RE.search(message)
        if m:
            await event_bus.publish(
                Event(
                    ts=now(),
                    source="journal",
                    kind="ssh_failed_password",
                    data={"src_ip": m.group(1), "message": message},
                )
            )
        return

    if identifier == "sudo" and (
        "authentication failure" in message or "incorrect password" in message.lower()
    ):
        m = _SUDO_USER_RE.match(message)
        await event_bus.publish(
            Event(
                ts=now(),
                source="journal",
                kind="sudo_failed",
                data={"user": m.group(1) if m else "unknown", "message": message},
            )
        )
        return

    if identifier == "kernel":
        if "New USB device found" in message:
            await event_bus.publish(
                Event(ts=now(), source="journal", kind="usb_new", data={"message": message})
            )
            return
        m = _PROMISC_RE.search(message)
        if m:
            await event_bus.publish(
                Event(
                    ts=now(),
                    source="journal",
                    kind="promisc_mode",
                    data={"interface": m.group(1), "message": message},
                )
            )
