"""Root helper with a deliberately tiny RPC surface."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
from pathlib import Path

from shield.agent import actions
from shield.security.response import stop_process
from shield.privileged.protocol import PrivilegedRequest

logger = logging.getLogger("shield.privileged")
MAX_REQUEST = 16 * 1024


async def dispatch(request: PrivilegedRequest) -> dict:
    action, params = request.action, request.params
    if action == "health":
        return {"request_id": request.request_id, "ok": True, "action": action, "message": "helper healthy"}
    if action == "block_ip": result = await actions.block_ip(params["ip"])
    elif action == "unblock_ip": result = await actions.unblock_ip(params["ip"])
    elif action == "block_mac": result = await actions.block_mac(params["mac"])
    elif action == "unblock_mac": result = await actions.unblock_mac(params["mac"])
    elif action == "rate_limit_ip": result = await actions.rate_limit_ip(params["ip"])
    elif action == "unrate_limit_ip": result = await actions.unrate_limit_ip(params["ip"])
    elif action == "isolate_endpoint":
        result = await actions.apply_isolation(params["management_ip"], params["preserve_dns"])
    elif action == "release_isolation":
        result = await actions.release_isolation()
    elif action == "stop_process":
        item = await asyncio.to_thread(stop_process, params["pid"], params["start_ticks"], dry_run=False)
        return {"request_id": request.request_id, **item.__dict__}
    else:  # guarded by PrivilegedRequest
        raise ValueError("unsupported action")
    ok, message = result
    return {"request_id": request.request_id, "ok": ok, "action": action, "message": message}


class HelperServer:
    def __init__(self, path: Path, allowed_uid: int) -> None:
        self.path, self.allowed_uid, self.server = path, allowed_uid, None

    async def handle(self, reader, writer) -> None:
        raw_socket = writer.get_extra_info("socket")
        try:
            _pid, uid, _gid = struct.unpack("3i", raw_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            # CHỈ chấp nhận theo UID: root (agent chạy User=root) hoặc đúng UID
            # agent đã cấu hình. KHÔNG chấp nhận theo group nữa — người gọi hợp
            # lệ DUY NHẤT của helper này là agent (đã kiểm: UI chỉ nói chuyện
            # với socket agent, không bao giờ chạm helper). Nhánh "primary GID
            # == group shield" trước đây nới quyền cho bất kỳ tiến trình nào có
            # primary group = shield được gọi root-helper (chặn IP / kill tiến
            # trình) — thừa và là bề mặt tấn công không cần thiết.
            if uid != 0 and uid != self.allowed_uid:
                raise PermissionError("peer UID not allowed")
            line = await reader.readline()
            if not line or len(line) > MAX_REQUEST:
                raise ValueError("invalid request size")
            request = PrivilegedRequest.parse(json.loads(line))
            response = await dispatch(request)
        except Exception as exc:
            response = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
        writer.write((json.dumps(response) + "\n").encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def run(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists(): self.path.unlink()
        self.server = await asyncio.start_unix_server(self.handle, path=str(self.path), limit=MAX_REQUEST)
        os.chmod(self.path, 0o660)
        async with self.server:
            await self.server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    path = Path(os.environ.get("SHIELD_HELPER_SOCK", "/run/shield-helper/helper.sock"))
    allowed_uid = int(os.environ.get("SHIELD_AGENT_UID", "0"))
    asyncio.run(HelperServer(path, allowed_uid).run())


if __name__ == "__main__": main()
