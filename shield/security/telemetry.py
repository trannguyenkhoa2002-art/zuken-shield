"""Kernel telemetry capability selection and normalized event contracts.

Shield never silently claims eBPF coverage: the selected backend and reason are
reported to health/UI, with auditd and portable polling as explicit fallbacks.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, asdict
from pathlib import Path

from shield.common.models import Event


@dataclass(frozen=True)
class TelemetryCapability:
    """Backend nào sẽ được dùng — KHÔNG phải loại event nào thật sự thu được.

    `capabilities` là thứ backend này ĐƯỢC KỲ VỌNG cung cấp, suy ra từ việc dò
    file trên đĩa. Nó không phải bằng chứng. Trước 2.0, nhánh eBPF khai
    ("process", "file", "socket", ...) trong khi collector chỉ phát
    `process_exec`, và không có gì phát hiện ra mâu thuẫn đó.

    Coverage THẬT được đo lúc chạy bằng `kernel.probe_support()` — nó gắn từng
    probe vào kernel thật — rồi ghi vào collector health theo từng loại event.
    `measured=False` ở đây tồn tại để không ai đọc nhầm dự đoán thành sự kiện.
    """

    backend: str
    available: bool
    event_driven: bool
    reason: str
    capabilities: tuple[str, ...]
    measured: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class KernelTelemetrySelector:
    def __init__(self, root: Path = Path("/")) -> None:
        self.root = root

    def detect(self) -> TelemetryCapability:
        btf = self.root / "sys/kernel/btf/vmlinux"
        host_tools = self.root.resolve() == Path("/")
        if btf.is_file() and host_tools and shutil.which("bpftrace"):
            return TelemetryCapability(
                "ebpf", True, True,
                "kernel BTF and eBPF tooling detected; per-event coverage is measured at startup",
                # Đúng ba loại Shield thật sự cố thu, viết đúng tên kind để một
                # lỗi chính tả không thành một khả năng tưởng tượng.
                ("process_exec", "file_write", "socket_connect"),
            )
        audit_socket = self.root / "var/run/audispd_events"
        audit_log = self.root / "var/log/audit/audit.log"
        if (host_tools and shutil.which("ausearch")) or audit_socket.exists() or audit_log.exists():
            return TelemetryCapability(
                "auditd", True, True, "audit subsystem detected; eBPF unavailable",
                ("process", "protected_file", "identity"),
            )
        proc = self.root / "proc"
        return TelemetryCapability(
            "procfs", proc.is_dir(), False,
            "portable bounded polling fallback",
            ("process", "listener", "service", "usb") if proc.is_dir() else (),
        )


def normalize_kernel_record(record: dict, backend: str) -> Event:
    """Normalize an already-collected backend record; no command execution."""
    kind = str(record.get("kind", ""))
    if kind not in {"process_exec", "process_exit", "file_open", "file_write", "socket_connect", "listener_opened"}:
        raise ValueError("unsupported kernel telemetry kind")
    data = dict(record.get("data") or {})
    data["telemetry_backend"] = backend
    if "pid" in data:
        data["pid"] = int(data["pid"])
    if "ppid" in data:
        data["ppid"] = int(data["ppid"])
    return Event(float(record["ts"]), "kernel", kind, data)
