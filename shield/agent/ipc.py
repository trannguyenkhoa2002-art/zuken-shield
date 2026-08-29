"""Unix socket server: agent (root) -> UI (user thường), JSON lines.

Socket path dò theo thứ tự (giống store.py, distro-agnostic Ubuntu/Kali):
1. Biến môi trường SHIELD_SOCK.
2. /run/shield/shield.sock nếu thư mục ghi được — production, quyền 0660
   group `shield` (thư mục do `RuntimeDirectory=shield` của systemd tạo,
   group đúng nhờ `Group=shield` trong unit — xem systemd/shield-agent.service,
   không phải tmpfiles.d/chgrp tay, những cách đó KHÔNG ăn vì RuntimeDirectory
   tự tạo lại root:root mỗi lần service start nếu unit không khai Group=).
3. Fallback $XDG_RUNTIME_DIR/shield/shield.sock — dev, chạy không cần root/systemd.
   KHÔNG còn fallback về /tmp: /tmp là thư mục ai cũng ghi được, một user
   thường có thể tạo trước /tmp/shield rồi thay socket để giả mạo agent với
   UI (bơm alert giả, nuốt lệnh). Thiếu XDG_RUNTIME_DIR thì bắt buộc chỉ
   định SHIELD_SOCK, không đoán bừa.

Mỗi dòng gửi xuống UI là 1 JSON object kết thúc bằng \n:
    {"type": "alert", "data": {...}}
    {"type": "event",  "data": {...}}

UI gửi lên agent cũng JSON lines dạng lệnh, nhưng agent CHỈ nhận action_id
từ allowlist. Giai đoạn 1 chỉ có `trust_device` (ghi DB, không đụng hệ thống);
allowlist đầy đủ (block_ip, pin_gateway_arp, ...) sẽ ở actions.py giai đoạn 5.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import stat
import struct
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Awaitable, Callable

logger = logging.getLogger("shield.ipc")

CommandHandler = Callable[[dict], Awaitable[None]]
MAX_MESSAGE_BYTES = 64 * 1024
RATE_LIMIT_COMMANDS = 60
RATE_WINDOW_S = 10.0


def allowed_uids() -> set[int] | None:
    """UID được phép nối socket agent, đọc từ SHIELD_IPC_ALLOWED_UIDS.

    Mặc định (không đặt biến) giữ nguyên mô hình cũ: ai có quyền ghi lên
    socket đều nối được, tức mọi thành viên group `shield`. Đó là ranh giới
    tin cậy tương đương admin vì client nối được có thể chạy response
    (block_ip / stop_process chạy root qua helper) — xem docs/OPERATIONS.md.
    Khi cần siết trên máy nhiều người dùng, đặt biến này thành danh sách UID
    ngăn cách bằng dấu phẩy; lúc đó peer ngoài danh sách bị từ chối ngay
    (root vẫn luôn được phép, nếu không agent tự khoá chính mình).
    """
    raw = os.environ.get("SHIELD_IPC_ALLOWED_UIDS", "").strip()
    if not raw:
        return None
    uids = {0}
    for token in raw.split(","):
        token = token.strip()
        if token:
            uids.add(int(token))
    return uids


def default_socket_path() -> Path:
    env = os.environ.get("SHIELD_SOCK")
    if env:
        return Path(env)

    prod_candidate = Path("/run/shield/shield.sock")
    if prod_candidate.parent.exists() and os.access(prod_candidate.parent, os.W_OK):
        return prod_candidate

    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_dir:
        raise RuntimeError(
            "Không xác định được đường dẫn socket an toàn: /run/shield không ghi "
            "được và XDG_RUNTIME_DIR không được đặt. Chỉ định tường minh bằng "
            "biến môi trường SHIELD_SOCK."
        )
    return Path(runtime_dir) / "shield" / "shield.sock"


class IpcServer:
    """Broadcast JSON-lines cho tất cả UI client đang kết nối."""

    def __init__(
        self, sock_path: Path | None = None, on_command: CommandHandler | None = None
    ) -> None:
        self.sock_path = sock_path or default_socket_path()
        self._writers: list[asyncio.StreamWriter] = []
        self._clients: dict[str, asyncio.StreamWriter] = {}
        self._server: asyncio.AbstractServer | None = None
        self._on_command = on_command

    async def start(self) -> None:
        self.sock_path.parent.mkdir(parents=True, exist_ok=True)
        # Thư mục đã tồn tại có thể do người khác tạo sẵn (squatting): kẻ tấn
        # công sở hữu thư mục thì xoá/thay được socket bên trong dù socket
        # đang là 0660 của mình. Chỉ chấp nhận thư mục thuộc chính uid đang
        # chạy hoặc root, và không cho người ngoài ghi.
        parent_stat = self.sock_path.parent.stat()
        if parent_stat.st_uid not in (0, os.getuid()):
            raise PermissionError(
                f"Thư mục socket {self.sock_path.parent} thuộc uid {parent_stat.st_uid}, "
                "không phải uid đang chạy agent — từ chối để tránh bị giả mạo socket."
            )
        # World-writable KÈM sticky bit (kiểu /tmp, 1777) vẫn chấp nhận được:
        # sticky bit chặn user khác xoá/đổi tên file không phải của họ, nên
        # socket không bị thay. Không có sticky bit thì bất kỳ ai cũng unlink
        # được socket rồi dựng socket của mình vào đúng chỗ đó.
        if parent_stat.st_mode & 0o002 and not parent_stat.st_mode & stat.S_ISVTX:
            raise PermissionError(
                f"Thư mục socket {self.sock_path.parent} cho mọi user ghi mà không "
                "có sticky bit — từ chối để tránh bị thay socket."
            )
        if self.sock_path.exists():
            self.sock_path.unlink()

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=str(self.sock_path), limit=MAX_MESSAGE_BYTES
        )
        # 0660: chỉ owner (root) và group (shield) đọc/viết — user trong
        # group shield mới kết nối được. Trên dev fallback path này vô hại.
        os.chmod(self.sock_path, 0o660)
        logger.info("IPC socket lắng nghe tại %s", self.sock_path)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        raw_socket = writer.get_extra_info("socket")
        try:
            pid, uid, gid = struct.unpack("3i", raw_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        except (AttributeError, OSError, struct.error):
            logger.warning("Từ chối IPC client: không đọc được SO_PEERCRED")
            writer.close()
            await writer.wait_closed()
            return
        permitted = allowed_uids()
        if permitted is not None and uid not in permitted:
            logger.warning(
                "Từ chối IPC client uid=%s pid=%s: không nằm trong SHIELD_IPC_ALLOWED_UIDS", uid, pid
            )
            writer.close()
            await writer.wait_closed()
            return
        client_id = uuid.uuid4().hex
        peer = {"client_id": client_id, "pid": pid, "uid": uid, "gid": gid}
        recent_commands: deque[float] = deque()
        seen_requests: set[str] = set()
        request_order: deque[str] = deque(maxlen=2048)
        self._writers.append(writer)
        self._clients[client_id] = writer
        logger.info("UI client kết nối (tổng %d)", len(self._writers))
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if len(line) > MAX_MESSAGE_BYTES:
                    logger.warning("IPC message quá lớn từ uid=%s pid=%s", uid, pid)
                    break
                try:
                    msg = json.loads(line.decode("utf-8"))
                    logger.debug("Nhận từ UI: %s", msg)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logger.warning("UI gửi JSON không hợp lệ: %r", line)
                    continue
                if not isinstance(msg, dict) or not isinstance(msg.get("request_id"), str):
                    logger.warning("IPC command thiếu request_id từ uid=%s pid=%s", uid, pid)
                    continue
                request_id = msg["request_id"]
                if not request_id or len(request_id) > 128 or request_id in seen_requests:
                    await self.send_to(client_id, "command_error", {"request_id": request_id, "error": "invalid or replayed request"})
                    continue
                if len(request_order) == request_order.maxlen:
                    seen_requests.discard(request_order[0])
                request_order.append(request_id)
                seen_requests.add(request_id)
                now_ts = time.monotonic()
                while recent_commands and now_ts - recent_commands[0] > RATE_WINDOW_S:
                    recent_commands.popleft()
                if len(recent_commands) >= RATE_LIMIT_COMMANDS:
                    await self.send_to(client_id, "command_error", {"request_id": msg["request_id"], "error": "rate limit exceeded"})
                    continue
                recent_commands.append(now_ts)
                msg["_peer"] = peer
                if self._on_command is not None:
                    await self._on_command(msg)
        except (ConnectionResetError, asyncio.IncompleteReadError, ValueError):
            pass
        finally:
            if writer in self._writers:
                self._writers.remove(writer)
            self._clients.pop(client_id, None)
            logger.info("UI client ngắt kết nối (còn %d)", len(self._writers))

    async def send_to(self, client_id: str, msg_type: str, data: dict) -> bool:
        writer = self._clients.get(client_id)
        if writer is None:
            return False
        payload = (json.dumps({"type": msg_type, "data": data}) + "\n").encode("utf-8")
        try:
            writer.write(payload)
            await writer.drain()
            return True
        except (ConnectionResetError, BrokenPipeError):
            return False

    def has_clients(self) -> bool:
        """Có giao diện nào đang nghe không.

        Dùng để KHÔNG mã hoá JSON cho một dòng event mà không ai đọc. Ở nhịp
        ~11 event mỗi giây thì đó là công việc bỏ đi suốt ngày.
        """
        return bool(self._writers)

    async def broadcast(self, msg_type: str, data: dict) -> None:
        payload = (json.dumps({"type": msg_type, "data": data}) + "\n").encode("utf-8")
        dead: list[asyncio.StreamWriter] = []
        for w in self._writers:
            try:
                w.write(payload)
                await w.drain()
            except (ConnectionResetError, BrokenPipeError):
                dead.append(w)
        for w in dead:
            if w in self._writers:
                self._writers.remove(w)

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self.sock_path.exists():
            self.sock_path.unlink()
