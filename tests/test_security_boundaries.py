import asyncio
import json
import os
import random
import string
from pathlib import Path

import pytest

from shield.agent.collectors.auditd import parse_audit_message
from shield.agent.ipc import IpcServer, allowed_uids, default_socket_path
from shield.privileged.protocol import PrivilegedRequest
from shield.privileged.__main__ import HelperServer
from shield.security.rules import EventRule


def test_privileged_protocol_fuzz_rejects_unknown_actions_and_extra_fields():
    rng = random.Random(42)
    for _ in range(200):
        action = "".join(rng.choice(string.ascii_letters) for _ in range(12))
        raw = {"request_id": "fuzz", "action": action, "params": {"cmd": "anything"}}
        with pytest.raises(ValueError):
            PrivilegedRequest.parse(raw)
    with pytest.raises(ValueError):
        PrivilegedRequest.parse({
            "request_id": "x", "action": "block_ip", "params": {"ip": "192.0.2.1"},
            "injected": "field",
        })


def test_rule_parser_fuzz_never_accepts_dynamic_execution_operator():
    base = {
        "id": "FUZZ", "version": 1, "kind": "event",
        "match": {"field": "value", "operator": "eval", "value": "__import__('os')"},
        "severity": "warning", "title": "x", "detail": "x", "subject_field": "value",
    }
    for operator in ("eval", "exec", "python", "regex-code", "__call__"):
        raw = json.loads(json.dumps(base))
        raw["match"]["operator"] = operator
        with pytest.raises(ValueError):
            EventRule.from_dict(raw)


def test_audit_parser_handles_untrusted_noise_without_exception():
    rng = random.Random(7)
    alphabet = string.printable
    for _ in range(1000):
        message = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 300)))
        result = parse_audit_message(message)
        assert result is None or result.source == "auditd"


def _short_sock() -> Path:
    # AF_UNIX giới hạn ~108 ký tự — tmp_path của pytest quá dài, dùng /tmp.
    import tempfile

    fd, name = tempfile.mkstemp(prefix="sh-", suffix=".sock", dir="/tmp")
    os.close(fd)
    os.unlink(name)
    return Path(name)


async def _helper_call(server: HelperServer, sock_path: Path, payload: str) -> str:
    srv = await asyncio.start_unix_server(server.handle, path=str(sock_path))
    try:
        reader, writer = await asyncio.open_unix_connection(str(sock_path))
        try:
            writer.write((payload + "\n").encode())
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), 5)
        except (ConnectionResetError, BrokenPipeError):
            # Bị từ chối SỚM (trước khi đọc request): helper đóng socket khiến
            # RST — coi như phản hồi từ chối, không phải lỗi test.
            return json.dumps({"ok": False, "error": "PermissionError"})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
        return line.decode() if line else json.dumps({"ok": False, "error": "PermissionError"})
    finally:
        srv.close()
        await srv.wait_closed()
        sock_path.unlink(missing_ok=True)


def test_helper_accepts_own_uid_and_health():
    """Peer trùng allowed_uid được chấp nhận (health không cần quyền gì)."""
    sock = _short_sock()
    server = HelperServer(sock, allowed_uid=os.getuid())
    payload = json.dumps({"request_id": "r1", "action": "health", "params": {}})
    resp = json.loads(asyncio.run(_helper_call(server, sock, payload)))
    assert resp["ok"] is True


def test_helper_rejects_wrong_uid_even_with_matching_gid():
    """Sau khi siết: KHÔNG còn chấp nhận theo group. Helper không còn tham số
    allowed_gid nào để cấu hình, nên peer có cùng gid với tiến trình đang chạy
    helper vẫn phải bị từ chối khi uid lệch (trước đây nhánh gid cho qua)."""
    if os.getuid() == 0:
        pytest.skip("chạy bằng root thì uid==0 luôn được chấp nhận")
    sock = _short_sock()
    server = HelperServer(sock, allowed_uid=os.getuid() + 12345)
    payload = json.dumps({"request_id": "r1", "action": "health", "params": {}})
    resp = json.loads(asyncio.run(_helper_call(server, sock, payload)))
    assert resp["ok"] is False
    assert resp["error"] == "PermissionError"


# --- Ranh giới socket agent (không phải helper root) ---


def test_allowed_uids_defaults_to_open_and_always_keeps_root(monkeypatch):
    """Không đặt biến -> None (giữ mô hình group `shield`). Đặt rồi thì root
    luôn có trong tập, nếu không agent chạy bằng root tự khoá chính mình."""
    monkeypatch.delenv("SHIELD_IPC_ALLOWED_UIDS", raising=False)
    assert allowed_uids() is None
    monkeypatch.setenv("SHIELD_IPC_ALLOWED_UIDS", "1000, 1001 ,")
    assert allowed_uids() == {0, 1000, 1001}


def test_ipc_rejects_peer_outside_allowed_uids(monkeypatch):
    """Peer không nằm trong allowlist bị đóng kết nối trước khi lệnh nào chạy,
    kể cả khi nó có quyền ghi lên socket (tức đã ở trong group `shield`)."""
    if os.getuid() == 0:
        pytest.skip("chạy bằng root thì uid==0 luôn được phép")
    monkeypatch.setenv("SHIELD_IPC_ALLOWED_UIDS", str(os.getuid() + 12345))
    sock = _short_sock()
    received: list[dict] = []

    async def scenario() -> bytes:
        async def on_command(msg: dict) -> None:
            received.append(msg)

        server = IpcServer(sock_path=sock, on_command=on_command)
        await server.start()
        try:
            reader, writer = await asyncio.open_unix_connection(str(sock))
            writer.write(json.dumps({"request_id": "r1", "cmd": "trust_device"}).encode() + b"\n")
            await writer.drain()
            try:
                leftover = await asyncio.wait_for(reader.read(), timeout=5)
            except ConnectionResetError:
                leftover = b""   # server đóng phía nó — cũng là bị từ chối
            writer.close()
            return leftover
        finally:
            await server.close()

    assert asyncio.run(scenario()) == b""   # server đóng ngay, không trả gì
    assert received == []                    # và không lệnh nào tới handler


def test_ipc_refuses_socket_dir_that_anyone_can_replace(tmp_path):
    """Thư mục ai cũng ghi được mà không có sticky bit -> kẻ tấn công unlink
    socket rồi dựng socket của mình vào đúng đường dẫn đó."""
    import tempfile

    parent = Path(tempfile.mkdtemp(prefix="sh-open-", dir="/tmp"))
    os.chmod(parent, 0o777)
    server = IpcServer(sock_path=parent / "shield.sock")
    with pytest.raises(PermissionError):
        asyncio.run(server.start())
    os.chmod(parent, 0o755)
    parent.rmdir()


def test_socket_path_never_falls_back_to_shared_tmp(monkeypatch):
    """Không còn đoán /tmp/shield/shield.sock — thiếu cấu hình thì báo lỗi rõ."""
    monkeypatch.delenv("SHIELD_SOCK", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    if os.access("/run/shield", os.W_OK):
        # Máy đang cài Shield: đi nhánh production, vẫn không được ra /tmp.
        assert default_socket_path() == Path("/run/shield/shield.sock")
    else:
        with pytest.raises(RuntimeError, match="SHIELD_SOCK"):
            default_socket_path()
