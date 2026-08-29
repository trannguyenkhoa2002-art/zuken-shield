"""Local fleet registry and certificate identity validation, without shell RPC."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
import time
import uuid
from dataclasses import dataclass


# `probe` là role THẤP NHẤT và cố ý KHÔNG có mặt trong bảng quyền của
# `authorize()` — nghĩa là một probe không chạy được bất kỳ lệnh nào trong
# FLEET_COMMANDS. Probe chỉ gửi log lên (xem collectors/log_ingest.py); nó
# không bao giờ được nhận lệnh xuống.
FLEET_ROLES = {"probe", "viewer", "analyst", "administrator"}
FLEET_COMMANDS = {"request_health", "request_assessment", "push_signed_rules", "push_signed_config"}
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
MAX_FLEET_MESSAGE = 64 * 1024


@dataclass(frozen=True)
class EndpointIdentity:
    endpoint_id: str
    display_name: str
    certificate_fingerprint: str
    role: str
    enrolled_ts: float


def certificate_fingerprint(pem: bytes) -> str:
    if len(pem) > 128 * 1024:
        raise ValueError("invalid certificate envelope")
    try:
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid certificate envelope") from exc
    if not der:
        raise ValueError("empty certificate")
    return hashlib.sha256(der).hexdigest()


class FleetRegistry:
    def __init__(self, store) -> None:
        self.store = store

    def enroll(self, display_name: str, certificate_pem: bytes, role: str = "viewer") -> EndpointIdentity:
        if role not in FLEET_ROLES or not display_name.strip():
            raise ValueError("invalid endpoint enrollment")
        item = EndpointIdentity(uuid.uuid4().hex, display_name.strip()[:120], certificate_fingerprint(certificate_pem), role, time.time())
        self.store.upsert_endpoint(item.__dict__)
        return item

    def enroll_fingerprint(self, display_name: str, fingerprint: str, role: str = "probe") -> EndpointIdentity:
        """Ghi danh khi chỉ có fingerprint, không có file certificate.

        generate-probe-ca.sh in fingerprint ngay lúc phát chứng chỉ, nên
        người quản trị không phải chép file .crt ngược về máy Shield chỉ để
        ghi danh — càng ít lần chép khoá qua lại càng ít cơ hội rò rỉ.
        """
        fingerprint = (fingerprint or "").strip().lower().replace(":", "")
        if role not in FLEET_ROLES or not display_name.strip():
            raise ValueError("invalid endpoint enrollment")
        if not _FINGERPRINT.fullmatch(fingerprint):
            raise ValueError("fingerprint must be 64 hex characters (SHA256 of the DER certificate)")
        item = EndpointIdentity(uuid.uuid4().hex, display_name.strip()[:120], fingerprint, role, time.time())
        self.store.upsert_endpoint(item.__dict__)
        return item

    def authorize(self, fingerprint: str, command: str) -> bool:
        if not _FINGERPRINT.fullmatch(fingerprint) or command not in FLEET_COMMANDS:
            return False
        endpoint = self.store.get_endpoint_by_fingerprint(fingerprint)
        if not endpoint:
            return False
        required = {"request_health": "viewer", "request_assessment": "analyst",
                    "push_signed_rules": "administrator", "push_signed_config": "administrator"}[command]
        rank = {"probe": -1, "viewer": 0, "analyst": 1, "administrator": 2}
        if endpoint["role"] == "probe":
            return False  # probe chỉ gửi log lên, không bao giờ nhận lệnh xuống
        return rank[endpoint["role"]] >= rank[required]


class FleetControlServer:
    """Optional mTLS JSON server with a fixed command vocabulary."""

    def __init__(self, registry: FleetRegistry, context: ssl.SSLContext, handler,
                 host: str = "127.0.0.1", port: int = 9443) -> None:
        if context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("fleet server requires mutual TLS")
        self.registry, self.context, self.handler = registry, context, handler
        self.host, self.port, self.server = host, int(port), None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port, ssl=self.context,
                                                 limit=MAX_FLEET_MESSAGE)
        return self.server

    async def _handle(self, reader, writer) -> None:
        request_id = ""
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            if not certificate:
                raise PermissionError("client certificate required")
            fingerprint = hashlib.sha256(certificate).hexdigest()
            line = await asyncio.wait_for(reader.readline(), 5)
            if not line or len(line) > MAX_FLEET_MESSAGE:
                raise ValueError("invalid fleet request size")
            message = json.loads(line)
            if not isinstance(message, dict) or set(message) != {"request_id", "command", "payload"}:
                raise ValueError("invalid fleet request envelope")
            request_id, command, payload = str(message["request_id"]), str(message["command"]), message["payload"]
            if not request_id or len(request_id) > 128 or not isinstance(payload, dict):
                raise ValueError("invalid fleet request")
            if not self.registry.authorize(fingerprint, command):
                raise PermissionError("fleet command denied")
            endpoint = self.registry.store.get_endpoint_by_fingerprint(fingerprint)
            result = await asyncio.wait_for(self.handler(command, payload, endpoint), 60)
            response = {"ok": True, "request_id": request_id, "result": result}
        except Exception as exc:
            response = {"ok": False, "request_id": request_id, "error": type(exc).__name__, "message": str(exc)}
        writer.write((json.dumps(response) + "\n").encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()


def fleet_server_context(certificate: str, private_key: str, client_ca: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certificate, private_key)
    context.load_verify_locations(cafile=client_ca)
    return context
