"""Nói chuyện với systemd qua NOTIFY_SOCKET — không thêm dependency nào.

`python-systemd` là gói C cần biên dịch; giao thức thì chỉ là gửi một datagram
văn bản vào một Unix socket. Tự viết 30 dòng đáng giá hơn là kéo thêm một
dependency phải build offline lúc đóng .deb.

Dùng cho hai việc trong Shield:
- `notify("READY=1")` sau khi agent dựng xong collector (Type=notify).
- `notify("WATCHDOG=1")` theo chu kỳ, để `WatchdogSec=` trong unit file phát
  hiện agent treo — treo khác với chết, và `Restart=` không bắt được treo.
"""

from __future__ import annotations

import os
import socket

__all__ = ["notify", "watchdog_interval_s", "available"]


def available() -> bool:
    return bool(os.environ.get("NOTIFY_SOCKET"))


def notify(message: str) -> bool:
    """Gửi một thông điệp trạng thái. Trả False nếu không chạy dưới systemd.

    Không bao giờ ném lỗi: agent không được phép chết chỉ vì không báo cáo
    được trạng thái cho systemd.
    """
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return False
    # "@" đầu chuỗi nghĩa là abstract namespace socket của Linux.
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            sock.connect(address)
            sock.sendall(message.encode("utf-8"))
        return True
    except (OSError, ValueError):
        return False


def watchdog_interval_s() -> float:
    """Chu kỳ nên ping, lấy từ WATCHDOG_USEC do systemd đặt.

    Ping ở NỬA chu kỳ theo khuyến nghị của systemd: nếu ping đúng bằng hạn
    chót thì chỉ cần một lần trễ nhỏ là bị giết oan.
    """
    raw = os.environ.get("WATCHDOG_USEC", "")
    try:
        micro = int(raw)
    except ValueError:
        return 0.0
    if micro <= 0:
        return 0.0
    # WATCHDOG_PID có mặt nghĩa là chỉ tiến trình đó được phép ping.
    pid = os.environ.get("WATCHDOG_PID")
    if pid and pid.isdigit() and int(pid) != os.getpid():
        return 0.0
    return micro / 2_000_000.0
