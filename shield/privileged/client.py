"""Coordinator client for the minimal privileged helper."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from shield.privileged.protocol import PrivilegedRequest


class PrivilegedClient:
    def __init__(self, path: Path, timeout_s: float = 10.0) -> None:
        self.path, self.timeout_s = path, timeout_s

    async def call(self, action: str, params: dict) -> dict:
        request = PrivilegedRequest.parse({"request_id": uuid.uuid4().hex, "action": action, "params": params})

        async def exchange() -> dict:
            reader, writer = await asyncio.open_unix_connection(str(self.path), limit=16 * 1024)
            try:
                writer.write((json.dumps({"request_id": request.request_id, "action": request.action, "params": request.params}) + "\n").encode())
                await writer.drain()
                line = await reader.readline()
                if not line or len(line) > 16 * 1024:
                    raise RuntimeError("invalid privileged helper response")
                response = json.loads(line)
                if response.get("request_id") not in {None, request.request_id}:
                    raise RuntimeError("privileged helper response ID mismatch")
                return response
            finally:
                writer.close()
                await writer.wait_closed()

        return await asyncio.wait_for(exchange(), self.timeout_s)
