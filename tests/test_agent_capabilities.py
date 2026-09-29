"""Bounding set của shield-agent: đo được, không nới dần.

Tập được chọn bằng cách chạy scripts/verify-agent-capabilities.py và
scripts/verify-kernel-telemetry.py bên trong đúng bounding set đó (container
privileged, cùng kernel với máy thật): mọi thao tác cần thiết PASS, lượt đối
chứng bỏ BPF/PERFMON/NET_ADMIN FAIL đúng 3 thao tác. Log trong thư mục bằng
chứng của đợt kiểm tra.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UNIT = (ROOT / "systemd/shield-agent.service").read_text(encoding="utf-8")
MEASURED = {
    "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_BPF", "CAP_PERFMON",
    "CAP_SYS_RESOURCE", "CAP_IPC_LOCK", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH",
    "CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER", "CAP_KILL", "CAP_AUDIT_READ",
}
NEVER = {"CAP_SYS_ADMIN", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
         "CAP_MKNOD", "CAP_SYS_TIME", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_SYS_BOOT"}


def _bounding_set() -> set[str]:
    match = re.search(r"^CapabilityBoundingSet=(.+)$", UNIT, re.MULTILINE)
    assert match, "agent unit has no CapabilityBoundingSet"
    return set(match.group(1).split())


def test_the_agent_keeps_exactly_the_measured_capabilities():
    assert _bounding_set() == MEASURED


def test_the_agent_can_never_regain_dangerous_capabilities():
    assert not (_bounding_set() & NEVER)
    assert re.search(r"^NoNewPrivileges=yes$", UNIT, re.MULTILINE)
    assert "AmbientCapabilities" not in UNIT


def test_the_measurement_scripts_ship_with_the_repository():
    script = (ROOT / "scripts/verify-agent-capabilities.py").read_text(encoding="utf-8")
    for probe in ("ptrace", "net_admin", "net_raw", "net_bind_service", "fowner", "dac_override", "bpftrace"):
        assert probe in script, probe
    for forbidden in ("setuid", "mknod", "sys_module"):
        assert forbidden in script, forbidden


def test_the_ui_graph_dependencies_are_declared():
    """Máy thật 29/09/2026: pyqtgraph có mặt nhưng thiếu PySide6.QtOpenGL, và
    giao diện báo sai "chưa cài pyqtgraph"."""
    control = (ROOT / "packaging/debian/control").read_text(encoding="utf-8")
    depends = next(line for line in control.splitlines() if line.startswith("Depends:"))
    for package in ("python3-pyside6.qtopengl", "python3-pyside6.qtopenglwidgets"):
        assert package in depends, package
    # pyqtgraph kéo PyQt (GPL) trên Ubuntu: chỉ gợi ý, không bắt buộc.
    assert "python3-pyqtgraph" not in depends


def test_the_display_version_follows_the_package_version():
    import shield

    assert shield._display("3.0.0a4") == "3.0 Alpha 4"
    assert shield._display("3.1.0rc2") == "3.1 RC 2"
    assert shield._display("4.0.0") == "4.0"
    assert shield.__display_version__ == shield._display(shield.__version__)
