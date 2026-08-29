"""Sanitized diagnostic export without database, secrets, PCAP, or quarantine content."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import zipfile
from pathlib import Path

from shield import __version__
from shield.security.health import RetentionPolicy

_SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|private.?key|credential|wifi|psk)")
_INLINE_SECRET = re.compile(r"(?i)\b(password|secret|token|psk)\s*[=:]\s*\S+")


def _command(args: list[str], timeout: float = 5.0) -> dict:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    output = _INLINE_SECRET.sub(lambda match: f"{match.group(1)}=<redacted>", result.stdout + result.stderr)
    return {"ok": result.returncode == 0, "returncode": result.returncode, "output": output[-32_000:]}


def sanitize(value):
    if isinstance(value, dict):
        return {
            str(key): "<redacted>" if _SECRET_KEY.search(str(key)) else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return _INLINE_SECRET.sub(lambda match: f"{match.group(1)}=<redacted>", value)
    return value


def diagnostic_payload(store) -> dict:
    integrity_ok, integrity_detail = store.check_integrity()
    policy = RetentionPolicy.from_env()
    return sanitize({
        "schema_version": 1,
        "created_ts": time.time(),
        "shield_version": __version__,
        "platform": {
            "os_release": Path("/etc/os-release").read_text(errors="replace")[:16_000]
            if Path("/etc/os-release").exists() else "unavailable",
            "python": os.sys.version,
        },
        "services": {
            "shield-agent": _command(["systemctl", "show", "shield-agent.service", "--no-pager",
                                       "--property=ActiveState,SubState,NRestarts,ExecMainStatus"]),
            "shield-privileged": _command(["systemctl", "show", "shield-privileged.service", "--no-pager",
                                            "--property=ActiveState,SubState,NRestarts,ExecMainStatus"]),
        },
        "recent_errors": _command([
            "journalctl", "--no-pager", "-p", "0..3", "-n", "100",
            "-u", "shield-agent.service", "-u", "shield-privileged.service",
        ]),
        "collector_health": store.collector_health(),
        "system_health": store.system_health(),
        "database": {**store.database_stats(), "integrity_ok": integrity_ok,
                     "integrity_detail": integrity_detail},
        "retention": policy.__dict__,
        "configuration": {
            "automatic_backup_enabled": store.get_baseline("automatic_backup_enabled") != "0",
            "config_schema_version": int(store.get_baseline("config_schema_version") or 0),
            "signed_rules_enabled": bool(os.environ.get("SHIELD_RULE_PUBLIC_KEY")),
            "signed_config_enabled": bool(os.environ.get("SHIELD_CONFIG_PUBLIC_KEY")),
            "audit_hmac_enabled": bool(os.environ.get("SHIELD_AUDIT_HMAC_KEY")),
            "fleet_enabled": bool(os.environ.get("SHIELD_FLEET_SERVER_CERT")),
            "pcap_enabled": bool(os.environ.get("SHIELD_PCAP_DIR")),
        },
    })


def export_diagnostic_bundle(store, destination: Path) -> dict:
    destination = destination.expanduser().absolute()
    if destination.is_symlink():
        raise ValueError("diagnostic destination must not be a symlink")
    destination = destination.parent.resolve() / destination.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(diagnostic_payload(store), indent=2, ensure_ascii=False, sort_keys=True).encode()
    manifest = {
        "schema_version": 1, "shield_version": __version__, "created_ts": time.time(),
        "files": {"diagnostics.json": hashlib.sha256(payload).hexdigest()},
        "excluded": ["database content", "Wi-Fi passwords", "private keys", "quarantine content", "PCAP"],
    }
    temp = destination.with_suffix(destination.suffix + ".tmp")
    if temp.is_symlink():
        raise ValueError("diagnostic temporary path must not be a symlink")
    with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("diagnostics.json", payload)
        bundle.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    os.chmod(temp, 0o600)
    os.replace(temp, destination)
    return manifest
