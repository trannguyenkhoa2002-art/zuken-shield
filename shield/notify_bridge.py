"""shield-notify: đưa thông báo của agent lên màn hình người dùng.

Chạy như một systemd USER service trong phiên desktop, bằng chính quyền của
người dùng (thành viên nhóm `shield`, nên mở được socket agent). Nó làm hai
việc:

1. Nhận bản tin `desktop_notification` (agent đã che bí mật) và gọi
   notify-send. Không có chuyển quyền nào: đó là lý do nó tồn tại — xem ghi
   chú ở đầu phần desktop trong shield/agent/notifier.py.

2. Báo khi MẤT agent. Agent chết thì nó không tự báo được, và guardian (chỉ
   đọc, không mạng, không phiên desktop) chỉ ghi được vào journal và database.
   Ngày 27/09/2026 agent nằm ở trạng thái failed nhiều giờ mà người dùng không
   hề biết. Mất kết nối quá `AGENT_LOSS_GRACE_S` giây — đủ lâu để một lần
   restart bình thường không gây báo động giả — thì báo một lần; nối lại được
   thì báo đã hồi phục.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
import uuid
from pathlib import Path

from shield.agent.ipc import SUBSCRIBE_NOTIFICATIONS, default_socket_path
from shield.agent.notifier import run_notify_send

logger = logging.getLogger("shield.notify")

AGENT_LOSS_GRACE_S = 120.0
RECONNECT_DELAY_S = 5.0
MAX_LINE_BYTES = 1024 * 1024

LOST_TITLE = "Shield: agent không chạy"
LOST_BODY = ("Không kết nối được tới shield-agent quá {seconds:.0f} giây — máy này hiện "
             "KHÔNG được giám sát. Kiểm tra: systemctl status shield-agent")
RECOVERED_TITLE = "Shield: agent đã chạy lại"
RECOVERED_BODY = "Kết nối tới shield-agent đã phục hồi; giám sát tiếp tục."


class AgentWatch:
    """Trạng thái kết nối tới agent và quyết định khi nào phải báo.

    Tách khỏi vòng I/O để kiểm thử được bằng đồng hồ giả.
    """

    def __init__(self, grace_s: float = AGENT_LOSS_GRACE_S, now: float | None = None) -> None:
        self.grace_s = grace_s
        self.disconnected_since: float | None = time.monotonic() if now is None else now
        self.loss_reported = False

    def connected(self) -> bool:
        """Gọi khi nối được. True nghĩa là phải báo "đã phục hồi"."""
        recovered = self.loss_reported
        self.disconnected_since = None
        self.loss_reported = False
        return recovered

    def disconnected(self, now: float) -> None:
        if self.disconnected_since is None:
            self.disconnected_since = now

    def should_report_loss(self, now: float) -> bool:
        if self.loss_reported or self.disconnected_since is None:
            return False
        if now - self.disconnected_since >= self.grace_s:
            self.loss_reported = True
            return True
        return False


async def handle_line(line: bytes) -> bool:
    """Xử lý một dòng từ agent. Trả True nếu đã hiện một thông báo."""
    try:
        msg = json.loads(line.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(msg, dict) or msg.get("type") != "desktop_notification":
        return False
    data = msg.get("data")
    if not isinstance(data, dict):
        return False
    title, body = data.get("title"), data.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return False
    return await run_notify_send(title[:200], body[:1000])


async def session(sock_path: Path, watch: AgentWatch) -> None:
    """Một phiên kết nối: đăng ký, rồi đọc tới khi agent đóng socket."""
    reader, writer = await asyncio.open_unix_connection(str(sock_path), limit=MAX_LINE_BYTES)
    try:
        request = {"cmd": SUBSCRIBE_NOTIFICATIONS, "request_id": uuid.uuid4().hex}
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        logger.info("Đã nối shield-agent tại %s", sock_path)
        if watch.connected():
            await run_notify_send(RECOVERED_TITLE, RECOVERED_BODY, urgency="normal")
        while True:
            try:
                line = await reader.readline()
            except ValueError:
                # Dòng vượt MAX_LINE_BYTES (UI broadcast lớn): bỏ, đọc tiếp.
                continue
            if not line:
                return
            await handle_line(line)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def run(sock_path: Path, grace_s: float = AGENT_LOSS_GRACE_S) -> None:
    watch = AgentWatch(grace_s)
    while True:
        try:
            await session(sock_path, watch)
            logger.warning("shield-agent đóng kết nối")
        except (OSError, ConnectionError) as exc:
            logger.debug("Chưa nối được shield-agent: %s", exc)
        now = time.monotonic()
        watch.disconnected(now)
        if watch.should_report_loss(now):
            logger.warning("Mất shield-agent quá %.0f giây", grace_s)
            await run_notify_send(LOST_TITLE, LOST_BODY.format(seconds=grace_s))
        await asyncio.sleep(RECONNECT_DELAY_S)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="shield-notify",
        description="Hiện thông báo của Shield trong phiên desktop và báo khi agent ngừng chạy.",
    )
    parser.add_argument("--socket", type=Path, default=None, help="Socket IPC của agent")
    parser.add_argument("--grace", type=float, default=AGENT_LOSS_GRACE_S,
                        help="Số giây mất kết nối trước khi báo agent không chạy")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(run(args.socket or default_socket_path(), args.grace))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
