"""Agent integrity snapshot and clock rollback detection."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path


def hash_tree(root: Path, limit: int = 10_000) -> dict[str, str]:
    root = root.resolve()
    result = {}
    for number, path in enumerate(sorted(root.rglob("*")), 1):
        if number > limit:
            raise ValueError("integrity tree limit exceeded")
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def signed_snapshot(root: Path, key: bytes = b"") -> dict:
    payload = {"schema_version": 1, "created_ts": time.time(), "root": str(root.resolve()), "files": hash_tree(root)}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["hmac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest() if key else ""
    return payload


def verify_snapshot(snapshot: dict, root: Path, key: bytes = b"") -> tuple[bool, list[str]]:
    copy = dict(snapshot)
    signature = str(copy.pop("hmac", ""))
    if key:
        canonical = json.dumps(copy, sort_keys=True, separators=(",", ":")).encode()
        if not signature or not hmac.compare_digest(signature, hmac.new(key, canonical, hashlib.sha256).hexdigest()):
            return False, ["snapshot authentication failed"]
    current = hash_tree(root)
    expected = copy.get("files") or {}
    changed = sorted(path for path in set(current) | set(expected) if current.get(path) != expected.get(path))
    return not changed, changed


class ClockMonitor:
    def __init__(self, tolerance_s: float = 5.0) -> None:
        self.tolerance_s = tolerance_s
        self.wall = time.time()
        self.monotonic = time.monotonic()

    def check(self) -> dict:
        wall, mono = time.time(), time.monotonic()
        expected = self.wall + (mono - self.monotonic)
        drift = wall - expected
        self.wall, self.monotonic = wall, mono
        return {"ok": drift >= -self.tolerance_s, "drift_s": drift, "clock_rollback": drift < -self.tolerance_s}
