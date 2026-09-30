#!/usr/bin/env python3
"""Kiểm chứng bounding set capability của shield-agent bằng thao tác THẬT.

Chạy như root, BÊN TRONG bounding set cần kiểm (ví dụ qua `capsh --drop=...`
hoặc chính unit systemd). In một dòng cho mỗi thao tác agent cần — OK/FAIL —
và một dòng cho mỗi thao tác agent KHÔNG được làm — BLOCKED/ALLOWED.

    sudo capsh --drop=cap_sys_module,... -- -c 'python3 scripts/verify-agent-capabilities.py'

Thoát 0 chỉ khi mọi thao tác cần thiết OK và mọi thao tác bị cấm BLOCKED.
Chỉ đụng tới tài nguyên tạm của chính nó (file tạm, table nft `shield_capcheck`
trong namespace đang chạy — dùng container/VM nếu không muốn sửa ruleset máy).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cmd: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()[:200]


def needed() -> list[tuple[str, bool, str]]:
    results = []

    # CAP_SYS_PTRACE: đọc exe của tiến trình KHÁC (làm giàu event, danh sách listener).
    try:
        target = os.readlink(Path("/proc/1") / "exe")
        results.append(("read /proc/1/exe (ptrace)", True, target))
    except OSError as exc:
        results.append(("read /proc/1/exe (ptrace)", False, str(exc)))

    ok, out = run(["ss", "-tlnp"])
    results.append(("ss -tlnp (socket inventory)", ok, out[:80]))

    ok, out = run(["nft", "add", "table", "inet", "shield_capcheck"])
    results.append(("nft add table (net_admin)", ok, out))
    ok, out = run(["nft", "delete", "table", "inet", "shield_capcheck"])
    results.append(("nft delete table (net_admin)", ok, out))

    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        raw.close()
        results.append(("AF_PACKET raw socket (net_raw)", True, ""))
    except OSError as exc:
        results.append(("AF_PACKET raw socket (net_raw)", False, str(exc)))

    try:
        low = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        low.bind(("127.0.0.1", 514))
        low.close()
        results.append(("bind udp/514 syslog (net_bind_service)", True, ""))
    except OSError as exc:
        results.append(("bind udp/514 syslog (net_bind_service)", False, str(exc)))

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "owned-by-other"
        path.write_text("x")
        try:
            os.chown(path, 65534, 65534)
            os.chmod(path, 0o660)          # chủ file là người khác -> cần fowner
            os.chown(path, 0, 0)
            results.append(("chown/chmod files of other owners (chown, fowner)", True, ""))
        except OSError as exc:
            results.append(("chown/chmod files of other owners (chown, fowner)", False, str(exc)))
        locked = Path(tmp) / "no-perms"
        locked.write_text("x")
        os.chown(locked, 65534, 65534)
        os.chmod(locked, 0o000)
        try:
            locked.read_text()
            results.append(("read a 000 file of another owner (dac_override)", True, ""))
        except OSError as exc:
            results.append(("read a 000 file of another owner (dac_override)", False, str(exc)))

    ok, out = run(["bpftrace", "-q", "--dry-run", "-e",
                   "tracepoint:syscalls:sys_enter_execve { printf(\"x\\n\"); }"])
    results.append(("bpftrace attach tracepoint (bpf/perfmon/sys_admin)", ok, out))
    return results


def forbidden() -> list[tuple[str, bool, str]]:
    """Thao tác agent KHÔNG cần. True = bị chặn (đúng mong muốn)."""
    results = []
    ok, out = run(["setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups", "true"])
    results.append(("change uid (setuid/setgid)", not ok, out))
    with tempfile.TemporaryDirectory() as tmp:
        ok, out = run(["mknod", str(Path(tmp) / "dev"), "c", "1", "3"])
        results.append(("create device node (mknod)", not ok, out))
    ok, out = run(["date", "-s", "@0"]) if os.environ.get("CAPCHECK_TRY_CLOCK") == "1" else (False, "skipped")
    results.append(("set the system clock (sys_time)", not ok, out))
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        rc = libc.init_module(None, 0, b"")      # EPERM nếu thiếu CAP_SYS_MODULE, EFAULT/EINVAL nếu có
        err = ctypes.get_errno()
        results.append(("load a kernel module (sys_module)", rc != 0 and err == 1, f"errno={err}"))
    except Exception as exc:  # noqa: BLE001
        results.append(("load a kernel module (sys_module)", False, str(exc)))
    return results


def main() -> int:
    if os.geteuid() != 0:
        print("chạy bằng root (trong bounding set cần kiểm)")
        return 2
    status = Path("/proc/self/status").read_text()
    print(next(line for line in status.splitlines() if line.startswith("CapBnd")))
    failures = 0
    for name, ok, detail in needed():
        print(f"{'OK     ' if ok else 'FAIL   '} needed    {name}  {detail}")
        failures += not ok
    for name, blocked, detail in forbidden():
        print(f"{'BLOCKED' if blocked else 'ALLOWED'} forbidden {name}  {detail}")
        failures += not blocked
    print("RESULT", "PASS" if not failures else f"FAIL ({failures})")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
