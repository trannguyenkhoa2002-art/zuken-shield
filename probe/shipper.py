"""Gửi batch NDJSON về Shield qua mTLS TLS 1.3.

Dùng lại đúng mô hình danh tính mà `shield/security/fleet.py` đã có: client
certificate, danh tính là SHA256 của DER. Không phát minh giao thức mới —
phần khó của bảo mật truyền tin đã được giải quyết ở đó rồi.

Giao thức đơn giản hết mức có thể, một dòng JSON mỗi chiều:

    -> {"probe_id": "...", "records": [...]}
    <- {"ok": true, "accepted": 42}

Không có lệnh nào đi từ server xuống probe. Đây là ràng buộc thiết kế, không
phải thiếu sót: một kênh có thể ra lệnh cho mọi máy trong LAN là thứ chỉ nên
tồn tại khi thật sự cần, và Shield 1.1 thì không cần.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import time

logger = logging.getLogger("shield.probe.shipper")

MAX_RESPONSE_BYTES = 64 * 1024
CONNECT_TIMEOUT_S = 15.0


def client_context(certificate: str, private_key: str, server_ca: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cafile=server_ca)
    context.load_cert_chain(certificate, private_key)
    return context


class Shipper:
    def __init__(self, config) -> None:
        self.config = config
        self.sent = 0
        self.failures = 0
        self.last_error = ""

    def _context(self) -> ssl.SSLContext:
        return client_context(
            self.config.certificate, self.config.private_key, self.config.server_ca
        )

    def send(self, records: list[dict], timeout: float = CONNECT_TIMEOUT_S) -> tuple[bool, int, str]:
        """Gửi một batch. Trả (ok, số dòng server nhận, thông báo).

        Chỉ khi ok=True và accepted>0 thì probe mới được xoá dòng khỏi spool.
        """
        if not records:
            return True, 0, "batch rỗng"
        payload = json.dumps(
            {"probe_id": self.config.probe_id, "records": records},
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"

        try:
            context = self._context()
            with socket.create_connection(
                (self.config.server_host, self.config.server_port), timeout=timeout
            ) as raw:
                with context.wrap_socket(raw, server_hostname=self.config.server_host) as tls:
                    tls.settimeout(timeout)
                    tls.sendall(payload)
                    response = self._read_line(tls)
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False, 0, self.last_error

        try:
            message = json.loads(response)
        except ValueError:
            self.failures += 1
            self.last_error = "server trả về dữ liệu không phải JSON"
            return False, 0, self.last_error

        if not message.get("ok"):
            self.failures += 1
            self.last_error = str(message.get("message", "server từ chối batch"))
            return False, 0, self.last_error

        accepted = int(message.get("accepted", 0))
        self.sent += accepted
        self.last_error = ""
        return True, accepted, "ok"

    @staticmethod
    def _read_line(tls) -> str:
        chunks = []
        total = 0
        deadline = time.monotonic() + CONNECT_TIMEOUT_S
        while time.monotonic() < deadline:
            chunk = tls.recv(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ValueError("server trả lời quá dài")
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        return b"".join(chunks).decode("utf-8", "replace").strip()
