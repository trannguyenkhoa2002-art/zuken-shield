"""Công tắc tắt/tạm dừng giám sát điều khiển từ app (shield/agent/switch.py).

Không cần Qt, không chạm mạng: switch chỉ là trạng thái + cổng chặn, còn phần
"collector có tôn trọng cổng chặn không" được kiểm bằng đọc mã nguồn giống
cách test_ui_wiring.py kiểm đường đi lệnh UI<->agent.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from shield.agent import switch as switch_module
from shield.agent.switch import ALL, MAX_PAUSE_S, SCOPES, MonitoringSwitch

ROOT = Path(__file__).resolve().parent.parent
AGENT_SRC = (ROOT / "shield" / "agent" / "__main__.py").read_text()
DISCOVERY_SRC = (ROOT / "shield" / "agent" / "collectors" / "discovery.py").read_text()
UI_SRC = (ROOT / "shield" / "ui" / "__main__.py").read_text()


@pytest.fixture(autouse=True)
def _clean_singleton():
    switch_module.reset_switch()
    yield
    switch_module.reset_switch()


def test_everything_is_allowed_until_the_operator_pauses_it():
    monitoring = MonitoringSwitch()
    assert all(monitoring.allows(scope) for scope in SCOPES)
    assert monitoring.state().paused == frozenset()


def test_pausing_active_scan_leaves_passive_monitoring_running():
    """Đây là điểm cốt lõi: ở mạng trường chỉ cần tắt phần CHỦ ĐỘNG. Nếu tắt
    luôn phần thụ động thì người dùng mất hẳn khả năng phát hiện tấn công."""
    monitoring = MonitoringSwitch()
    monitoring.pause("active_scan")
    assert not monitoring.allows("active_scan")
    assert monitoring.allows("passive")
    assert monitoring.allows("capture")


def test_pause_all_stops_every_scope():
    monitoring = MonitoringSwitch()
    monitoring.pause(ALL)
    assert not any(monitoring.allows(scope) for scope in SCOPES)


def test_timed_pause_resumes_itself_without_any_further_command():
    """Tạm dừng có thời hạn PHẢI tự hết hạn — nếu không, người dùng tắt lúc
    vào trường rồi quên bật lại, và máy ở nhà cũng không được bảo vệ."""
    clock = [1000.0]
    monitoring = MonitoringSwitch(clock=lambda: clock[0])
    monitoring.pause(ALL, duration_s=900)
    assert not monitoring.allows("active_scan")
    clock[0] += 899
    assert not monitoring.allows("active_scan")
    clock[0] += 2
    assert monitoring.allows("active_scan")


def test_pause_duration_is_capped_so_it_can_never_become_permanent():
    clock = [0.0]
    monitoring = MonitoringSwitch(clock=lambda: clock[0])
    monitoring.pause(ALL, duration_s=10 * MAX_PAUSE_S)
    resume_ts = min(monitoring.state().resume_ts.values())
    assert resume_ts <= MAX_PAUSE_S


def test_indefinite_pause_never_expires_on_its_own():
    clock = [0.0]
    monitoring = MonitoringSwitch(clock=lambda: clock[0])
    monitoring.pause(ALL)
    clock[0] += 10 * MAX_PAUSE_S
    assert not monitoring.allows("active_scan")


def test_resume_puts_every_scope_back():
    monitoring = MonitoringSwitch()
    monitoring.pause(ALL, duration_s=60)
    monitoring.resume(ALL)
    assert all(monitoring.allows(scope) for scope in SCOPES)


def test_unknown_scope_is_rejected_instead_of_silently_pausing_nothing():
    monitoring = MonitoringSwitch()
    with pytest.raises(ValueError):
        monitoring.pause("everything")
    with pytest.raises(ValueError):
        monitoring.pause("")


def test_zero_duration_is_rejected():
    """duration_s=0 phải là lỗi, không được lặng lẽ thành "tạm dừng vĩnh viễn"."""
    monitoring = MonitoringSwitch()
    with pytest.raises(ValueError):
        monitoring.pause(ALL, duration_s=0.0)


def test_pause_and_resume_are_written_to_the_audit_trail():
    """Guardian (mục B2) phân biệt "người dùng tự tắt" với "bị tấn công" chỉ
    dựa vào dấu vết này. Không ghi = hai việc nhìn giống hệt nhau."""

    class RecordingStore:
        def __init__(self):
            self.audit, self.forensic = [], []

        def add_audit_log(self, action, params, result):
            self.audit.append((action, params, result))

        def add_forensic_record(self, kind, payload):
            self.forensic.append((kind, payload))

    store = RecordingStore()
    monitoring = MonitoringSwitch(store)
    monitoring.pause("active_scan", reason="mạng trường học")
    monitoring.resume(ALL)
    assert [a for a, _p, _r in store.audit] == ["monitoring_pause", "monitoring_resume"]
    assert store.audit[0][1]["reason"] == "mạng trường học"
    assert [kind for kind, _payload in store.forensic] == ["switch", "switch"]


def test_a_broken_store_never_takes_the_switch_down_with_it():
    """Tắt giám sát là hành động khẩn cấp. Nó không được phép thất bại chỉ vì
    ghi log lỗi."""

    class BrokenStore:
        def add_audit_log(self, *_args):
            raise RuntimeError("đĩa đầy")

        def add_forensic_record(self, *_args):
            raise RuntimeError("đĩa đầy")

    monitoring = MonitoringSwitch(BrokenStore())
    monitoring.pause(ALL)
    assert not monitoring.allows("active_scan")


def test_module_level_gate_follows_the_registered_switch():
    monitoring = switch_module.set_switch(MonitoringSwitch())
    monitoring.pause("active_scan")
    assert switch_module.allows("active_scan") is False
    assert switch_module.allows("passive") is True


# --- collector có thật sự tôn trọng công tắc không ---


def test_the_noisy_scanners_all_check_the_switch_before_touching_the_network():
    """arp-scan/nmap/self-audit/quét dải là thứ khiến NAC của trường đánh dấu
    máy này. Mỗi hàm phải có cổng chặn, nếu không nút Tạm dừng chỉ là trang trí."""
    for function in ("run_quick_scan", "run_deep_scan", "run_self_audit", "run_range_scan"):
        body = re.search(rf"async def {function}\(.*?(?=\nasync def |\ndef |\Z)", AGENT_SRC, re.DOTALL)
        assert body, f"không tìm thấy {function}"
        assert 'switch.allows("active_scan")' in body.group(0), (
            f"{function} không kiểm tra công tắc — vẫn quét mạng khi người dùng đã tạm dừng"
        )


def test_the_discovery_collector_checks_the_switch_inside_its_loop():
    assert 'switch.allows("active_scan")' in DISCOVERY_SRC
    loop = DISCOVERY_SRC[DISCOVERY_SRC.index("async def discovery_loop"):]
    gate = loop.index('switch.allows("active_scan")')
    scan = loop.index("await run_arp_scan(interface)", loop.index("while True"))
    assert gate < scan, "cổng chặn phải nằm TRƯỚC lần arp-scan của mỗi vòng"


def test_the_ui_can_reach_every_switch_command():
    sent = set(re.findall(r'"cmd":\s*"([a-z_]+)"', UI_SRC))
    for command in ("pause_monitoring", "resume_monitoring", "monitoring_status_now", "shutdown_agent"):
        assert command in sent, f"UI không gửi được lệnh {command}"
        assert f'cmd == "{command}"' in AGENT_SRC, f"agent không xử lý lệnh {command}"


def test_shutting_down_is_audited_before_the_agent_stops():
    """Ghi sau khi tắt là ghi vào hư không — agent đã chết."""
    branch = AGENT_SRC[AGENT_SRC.index('elif cmd == "shutdown_agent":'):]
    branch = branch[: branch.index('elif cmd ==', 5)]
    assert branch.index("add_audit_log") < branch.index("SHUTDOWN.set()")
    assert branch.index("add_forensic_record") < branch.index("SHUTDOWN.set()")
