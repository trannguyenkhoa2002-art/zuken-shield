"""Versioned plugins for read-only enrichment and analysis."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from shield.security.supply_chain import verify_detached_signature

ALLOWED_PERMISSIONS = {"read_events", "read_alerts", "emit_annotation"}


@dataclass(frozen=True)
class PluginManifest:
    id: str
    name: str
    version: str
    api_version: int
    entrypoint: str
    permissions: frozenset[str]

    @classmethod
    def load(cls, directory: Path) -> "PluginManifest":
        raw = json.loads((directory / "plugin.json").read_text(encoding="utf-8"))
        required = {"id", "name", "version", "api_version", "entrypoint", "permissions"}
        if not required.issubset(raw):
            raise ValueError(f"plugin manifest missing {sorted(required - raw.keys())}")
        permissions = frozenset(raw["permissions"])
        if permissions - ALLOWED_PERMISSIONS:
            raise ValueError("plugin requests forbidden permissions")
        entrypoint = str(raw["entrypoint"])
        if Path(entrypoint).is_absolute() or ".." in Path(entrypoint).parts or not entrypoint.endswith(".py"):
            raise ValueError("plugin entrypoint must be a relative Python file")
        if int(raw["api_version"]) != 1:
            raise ValueError("unsupported plugin API version")
        return cls(str(raw["id"]), str(raw["name"]), str(raw["version"]), 1, entrypoint, permissions)


def discover_plugins(root: Path, public_key: Path | None = None, require_signed: bool = False) -> list[tuple[Path, PluginManifest]]:
    if not root.exists():
        return []
    found = []
    for directory in sorted(path for path in root.iterdir() if path.is_dir()):
        try:
            manifest = PluginManifest.load(directory)
            if not (directory / manifest.entrypoint).is_file():
                continue
            if public_key is not None or require_signed:
                if public_key is None:
                    continue
                signatures = (
                    (directory / "plugin.json", directory / "plugin.json.sig"),
                    (directory / manifest.entrypoint, directory / f"{manifest.entrypoint}.sig"),
                )
                if not all(verify_detached_signature(payload, signature, public_key)[0] for payload, signature in signatures):
                    continue
            found.append((directory, manifest))
        except (ValueError, OSError, json.JSONDecodeError):
            continue
    return found


async def run_plugin(directory: Path, manifest: PluginManifest, records: list[dict], timeout_s: float = 5.0) -> dict:
    """Run an explicitly configured trusted plugin with a narrow JSON contract.

    `-I` and a minimal environment reduce accidental coupling, but are not an OS
    sandbox. Plugins remain disabled by default and must be trusted by the admin.
    """
    entrypoint = (directory / manifest.entrypoint).resolve()
    if directory.resolve() not in entrypoint.parents:
        raise ValueError("entrypoint escapes plugin directory")
    payload = json.dumps({"api_version": 1, "records": records[:1000]}).encode()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-I", str(entrypoint), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        stdout, _stderr = await asyncio.wait_for(proc.communicate(payload), timeout_s)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"plugin {manifest.id} timed out") from None
    if proc.returncode != 0 or len(stdout) > 1024 * 1024:
        raise RuntimeError(f"plugin {manifest.id} failed or exceeded output limit")
    result = json.loads(stdout.decode("utf-8"))
    if not isinstance(result, dict) or set(result) - {"summary", "annotations"}:
        raise ValueError("plugin returned invalid response schema")
    return result
