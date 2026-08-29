"""Parse Linux Audit events delivered by journald (event-driven telemetry)."""

from __future__ import annotations

import re

from shield.common.models import Event, now

_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_EXEC_SYSCALLS = {"11", "59", "221"}  # i386, x86_64, aarch64 execve
_WATCH_KEYS = {"shield_identity", "shield_sudoers", "shield_systemd", "shield_cron"}


def _fields(message: str) -> dict[str, str]:
    output = {}
    for key, raw in _FIELD.findall(message):
        output[key] = raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw
    return output


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def parse_audit_message(message: str) -> Event | None:
    fields = _fields(message)
    audit_type = fields.get("type", "")
    if audit_type == "SYSCALL" and fields.get("syscall") in _EXEC_SYSCALLS and fields.get("success") == "yes":
        return Event(now(), "auditd", "process_exec", {
            "pid": _as_int(fields.get("pid"), 0), "ppid": _as_int(fields.get("ppid"), 0),
            "uid": _as_int(fields.get("uid"), -1), "auid": _as_int(fields.get("auid"), -1),
            "exe": fields.get("exe", ""), "comm": fields.get("comm", ""),
            "audit_id": fields.get("msg", ""),
        })
    key = fields.get("key", "")
    if key in _WATCH_KEYS and audit_type in {"SYSCALL", "PATH"}:
        return Event(now(), "auditd", "security_file_changed", {
            "key": key, "path": fields.get("name", ""), "pid": _as_int(fields.get("pid"), 0),
            "uid": _as_int(fields.get("uid"), -1), "exe": fields.get("exe", ""),
        })
    return None
