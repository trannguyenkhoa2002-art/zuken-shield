"""Detached signature and artifact-manifest verification using system OpenSSL."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_detached_signature(payload: Path, signature: Path, public_key: Path) -> tuple[bool, str]:
    for path in (payload, signature, public_key):
        if not path.is_file():
            return False, f"missing verification file: {path}"
    try:
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
             "-sigfile", str(signature), "-rawin", "-in", str(payload)],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError) as exc:
        return False, str(exc)
    return (proc.returncode == 0, "signature verified" if proc.returncode == 0 else proc.stderr.strip() or "invalid signature")


def verify_update_manifest(manifest_path: Path, artifact_dir: Path, public_key: Path | None = None, signature: Path | None = None) -> tuple[bool, list[str]]:
    if public_key is not None:
        if signature is None:
            return False, ["signature required"]
        ok, message = verify_detached_signature(manifest_path, signature, public_key)
        if not ok:
            return False, [message]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [str(exc)]
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("artifacts"), dict):
        return False, ["invalid update manifest schema"]
    errors = []
    root = artifact_dir.resolve()
    for relative, expected in manifest["artifacts"].items():
        path = (root / relative).resolve()
        if root not in path.parents or not path.is_file():
            errors.append(f"missing or unsafe artifact: {relative}")
        elif sha256_file(path) != str(expected).lower():
            errors.append(f"hash mismatch: {relative}")
    return not errors, errors
