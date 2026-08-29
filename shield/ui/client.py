"""QThread duy nhất làm I/O: đọc Unix socket, phát Signal(dict).

Quy tắc vàng UI PySide6 (KE-HOACH-SHIELD.md mục 1.5): main thread chỉ vẽ,
không subprocess, không time.sleep, không I/O chặn. Toàn bộ socket I/O
nằm ở đây, main thread chỉ nhận signal.
"""

from __future__ import annotations

import json
import socket
import threading
import uuid
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from shield.agent.ipc import default_socket_path


class SocketClient(QThread):
    message_received = Signal(dict)
    connection_status = Signal(bool)

    def __init__(self, sock_path: Path | None = None, parent=None) -> None:
        super().__init__(parent)
        self.sock_path = sock_path or default_socket_path()
        self._running = True
        self._sock: socket.socket | None = None
        self._send_lock = threading.Lock()

    def stop(self) -> None:
        self._running = False
        self.wait(3000)

    def send_command(self, msg: dict) -> bool:
        """Gửi 1 lệnh JSON-line lên agent. An toàn gọi từ main thread Qt —
        chỉ ghi vào socket, không đọc, nên không tranh chấp với vòng recv()."""
        with self._send_lock:
            if self._sock is None:
                return False
            try:
                msg = dict(msg)
                msg.setdefault("request_id", uuid.uuid4().hex)
                self._sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
                return True
            except OSError:
                return False

    def run(self) -> None:
        while self._running:
            try:
                self._connect_and_read()
            except (FileNotFoundError, ConnectionRefusedError, OSError):
                pass
            self.connection_status.emit(False)
            if self._running:
                self.sleep(2)  # retry — không dùng time.sleep trên main thread

    def _connect_and_read(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.sock_path))
            sock.settimeout(1.0)
            with self._send_lock:
                self._sock = sock
            self.connection_status.emit(True)
            try:
                buf = b""
                while self._running:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        continue
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line:
                            continue
                        try:
                            msg = json.loads(line.decode("utf-8"))
                        except json.JSONDecodeError:
                            continue
                        self.message_received.emit(msg)
            finally:
                with self._send_lock:
                    self._sock = None
