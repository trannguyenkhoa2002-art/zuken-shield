"""Cấu hình probe: /etc/shield-probe/config.json."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

DEFAULT_CONFIG_DIR = Path("/etc/shield-probe")
DEFAULT_SPOOL_DIR = Path("/var/lib/shield-probe/spool")
DEFAULT_PORT = 9443

# Trần mặc định. Đều chỉnh được, nhưng mặc định phải an toàn cho một máy
# bất kỳ trong mạng chứ không chỉ máy dev của người viết.
DEFAULT_SPOOL_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_RATE_PER_S = 200
DEFAULT_BATCH_LINES = 500
DEFAULT_BATCH_BYTES = 256 * 1024
DEFAULT_MEMORY_MAX_MB = 128

# Cùng bộ định danh mà collectors/journal.py đang lọc — probe không được phép
# gửi nhiều hơn agent local thu thập, nếu không hai nguồn sẽ lệch nhau.
DEFAULT_JOURNAL_IDENTIFIERS = ("sshd", "sudo", "su", "kernel", "systemd-logind", "cron")


@dataclass
class ProbeConfig:
    server_host: str = ""
    server_port: int = DEFAULT_PORT
    probe_id: str = ""
    display_name: str = ""
    certificate: str = ""
    private_key: str = ""
    server_ca: str = ""
    spool_dir: str = str(DEFAULT_SPOOL_DIR)
    spool_max_bytes: int = DEFAULT_SPOOL_MAX_BYTES
    rate_per_s: int = DEFAULT_RATE_PER_S
    batch_lines: int = DEFAULT_BATCH_LINES
    batch_bytes: int = DEFAULT_BATCH_BYTES
    journal_identifiers: list = field(default_factory=lambda: list(DEFAULT_JOURNAL_IDENTIFIERS))
    log_files: list = field(default_factory=list)
    # Audit cho tín hiệu tốt hơn journald nhiều (execve thật, không phải chuỗi
    # log), nhưng chỉ có nếu máy đó đã bật auditd. Không bật thì lượt đọc chỉ
    # trả về rỗng, không tốn gì.
    include_audit: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "ProbeConfig":
        known = set(cls.__dataclass_fields__)
        config = cls(**{k: v for k, v in raw.items() if k in known})
        config.server_port = int(config.server_port)
        config.spool_max_bytes = max(1024 * 1024, int(config.spool_max_bytes))
        config.rate_per_s = max(1, int(config.rate_per_s))
        config.batch_lines = max(1, min(int(config.batch_lines), 5000))
        config.batch_bytes = max(1024, min(int(config.batch_bytes), 4 * 1024 * 1024))
        return config

    def validate(self) -> None:
        missing = [
            name for name in ("server_host", "probe_id", "certificate", "private_key", "server_ca")
            if not getattr(self, name)
        ]
        if missing:
            raise ValueError(f"cấu hình probe thiếu: {', '.join(missing)}")
        for name in ("certificate", "private_key", "server_ca"):
            path = Path(getattr(self, name))
            if not path.is_file():
                raise ValueError(f"{name} không tồn tại: {path}")


def config_path() -> Path:
    return Path(os.environ.get("SHIELD_PROBE_CONFIG", DEFAULT_CONFIG_DIR / "config.json"))


def load(path: Path | None = None) -> ProbeConfig:
    path = path or config_path()
    return ProbeConfig.from_dict(json.loads(path.read_text(encoding="utf-8")))


def save(config: ProbeConfig, path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(config.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    return path
