"""Cổng giải thích trên ĐƯỜNG SẢN PHẨM (Phase 3D limited rollout).

Bất biến trung tâm: **báo cáo tất định luôn ra, và model chỉ được mời khi CẢ
HAI điều kiện đúng** — kịch bản đã chứng minh đủ, và người vận hành đã bật
provider bằng tay. Thiếu một trong hai thì `spawns = 0`: không phải "worker
chạy rồi bị bỏ kết quả", mà là không có worker nào.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.common.models import Alert
from shield.report.scenarios import (
    DISABLED_FOR_EXPLANATION,
    ENABLED_FOR_EXPLANATION,
    ENABLED_WITH_SCENARIO_GATING,
    EXPLANATION_MATURITY,
    EXPLANATION_SCENARIO_OVERRIDE,
    LOW_SAMPLE_CONFIDENCE,
    PROVISIONAL,
    UNKNOWN,
    explanation_enabled,
    explanation_maturity,
)
from shield.report.template import AiSlots, render

NOW = 1000.0


def _store(tmp_path):
    """Store với phần giải thích ĐÃ BẬT TAY.

    Các test ở đây kiểm cơ chế job, không kiểm việc đồng ý: cổng opt-in có
    test riêng trong `test_report_ui.py`. Bật ở đây một cách tường minh để
    mặc-định-tắt vẫn là mặc định thật ở nơi khác.
    """
    from shield.agent.__main__ import EXPLANATION_OPT_IN_KEY
    store = Store(tmp_path / "s.db")
    store.set_baseline(EXPLANATION_OPT_IN_KEY, "1")
    return store


def _incident(store, correlation_id, rule_id, subject="192.168.1.77"):
    store.insert_alert(Alert(NOW, rule_id, "warning", "t", "d", subject,
                             evidence={"src_ip": subject, "fail_count": 37},
                             playbook=["snapshot_state"]))
    row = store.open_or_update_incident(
        correlation_id=correlation_id, subject=subject, title="t", severity="warning",
        risk_score=61, evidence_strength=0.6, recommended_action="snapshot_state",
        contributing=[{"rule_id": rule_id, "ts": NOW, "severity": "warning",
                       "detail": ""}])
    return row["incident_id"] if isinstance(row, dict) else row


def _run(store, incident_id):
    from shield.agent.__main__ import run_investigation

    return asyncio.run(run_investigation(store, incident_id))


# --------------------------------------------------------------------------
# §2–3 bảng eligibility


def test_the_family_table_records_the_measured_decisions():
    assert EXPLANATION_MATURITY == {
        "AUTHENTICATION_ATTACK": ENABLED_FOR_EXPLANATION,
        "MALWARE_EXECUTION": ENABLED_WITH_SCENARIO_GATING,
        "RECONNAISSANCE": DISABLED_FOR_EXPLANATION,
    }


def test_malware_is_gated_per_scenario_not_per_family():
    """Tổng của họ đạt 95,7% chỉ vì mã tốt đông hơn mã yếu. Bật cả họ vì con số
    tổng nghĩa là để mã yếu đi nhờ."""
    assert EXPLANATION_SCENARIO_OVERRIDE == {
        "SUSPICIOUS_EXECUTION_CHAIN": ENABLED_FOR_EXPLANATION,
        "EXECUTION_FROM_SUSPICIOUS_PATH": DISABLED_FOR_EXPLANATION,
    }
    assert explanation_enabled("SUSPICIOUS_EXECUTION_CHAIN") is True
    assert explanation_enabled("EXECUTION_FROM_SUSPICIOUS_PATH") is False


def test_a_gated_family_scenario_without_a_decision_is_not_enabled():
    """Im lặng cho qua sẽ biến "bật theo mã" thành "bật cả họ"."""
    from shield.report import scenarios

    original = dict(scenarios.EXPLANATION_SCENARIO_OVERRIDE)
    try:
        scenarios.EXPLANATION_SCENARIO_OVERRIDE.clear()
        assert explanation_maturity("SUSPICIOUS_EXECUTION_CHAIN") == PROVISIONAL
        assert explanation_enabled("SUSPICIOUS_EXECUTION_CHAIN") is False
    finally:
        scenarios.EXPLANATION_SCENARIO_OVERRIDE.update(original)


def test_provisional_never_counts_as_enabled():
    """`PROVISIONAL` = "trông ổn nhưng chưa chứng minh". Một thứ chưa chứng
    minh không được chạy trên máy người dùng."""
    from shield.report import scenarios

    original = dict(scenarios.EXPLANATION_MATURITY)
    try:
        scenarios.EXPLANATION_MATURITY["AUTHENTICATION_ATTACK"] = PROVISIONAL
        assert explanation_enabled("SSH_BRUTE_FORCE") is False
    finally:
        scenarios.EXPLANATION_MATURITY.clear()
        scenarios.EXPLANATION_MATURITY.update(original)


def test_reconnaissance_stays_hard_disabled():
    for code in ("PORT_SCAN", "NEW_DEVICE_THEN_SCAN", "RECON_THEN_SSH_ATTACK",
                 "TARPIT_CONTACT"):
        assert explanation_enabled(code) is False, code


def test_unknown_is_always_deterministic_only():
    assert explanation_enabled(UNKNOWN) is False
    assert explanation_maturity(UNKNOWN) == DISABLED_FOR_EXPLANATION


def test_low_sample_scenarios_are_kept_for_observability_not_blocking():
    """Họ đã bật thì mã vẫn được giải thích, nhưng bằng chứng còn mỏng và điều
    đó phải đọc được."""
    assert "LOGIN_AT_UNUSUAL_TIME" in LOW_SAMPLE_CONFIDENCE
    assert explanation_enabled("LOGIN_AT_UNUSUAL_TIME") is True


# --------------------------------------------------------------------------
# §1 + §8 thứ tự cổng và mặc định tắt


def test_the_deterministic_report_is_produced_with_the_provider_disabled(
        tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    store = _store(tmp_path)
    payload = _run(store, _incident(store, "ACCUMULATED_AUTH_FAILURES",
                                    "LOCAL_SSH_BRUTEFORCE"))
    report = payload["incident_report"]
    assert report["incident_type"]["scenario_code"] == "REPEATED_AUTH_FAILURES"
    assert report["severity"]["level"] == "warning"
    assert payload["explanation"]["invoked"] is False
    assert payload["explanation"]["provider_configured"] == "disabled"


@pytest.mark.parametrize("correlation_id,rule_id,code", [
    ("CORRELATED_NEW_DEVICE_THEN_SCAN", "SCAN_PORTSCAN", "NEW_DEVICE_THEN_SCAN"),
    ("KHONG_CO_ANH_XA", "CHUA_TUNG_THAY", UNKNOWN),
])
def test_an_ineligible_scenario_never_spawns_a_worker(
        tmp_path, monkeypatch, correlation_id, rule_id, code):
    """`spawns = 0` phải là "không có worker nào", không phải "worker chạy rồi
    bị bỏ kết quả"."""
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    spawned = []

    import shield.ai.worker.supervisor as S

    async def refuse(self, *a, **kw):
        spawned.append(1)
        raise AssertionError("KHÔNG được sinh worker cho kịch bản chưa đủ chín")

    monkeypatch.setattr(S.WorkerSupervisor, "_spawn", refuse)
    store = _store(tmp_path)
    payload = _run(store, _incident(store, correlation_id, rule_id))
    assert payload["explanation"]["scenario_code"] == code
    assert payload["explanation"]["invoked"] is False
    assert spawned == [], "đã sinh worker cho kịch bản không đủ điều kiện"
    assert payload["incident_report"]["incident_type"]["scenario_code"] == code


def test_the_kill_switch_blocks_invocation_even_for_an_enabled_scenario(
        tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.setenv("SHIELD_AI_KILL_SWITCH", "1")
    spawned = []

    import shield.ai.worker.supervisor as S

    async def refuse(self, *a, **kw):
        spawned.append(1)
        raise AssertionError("kill switch bật mà vẫn sinh worker")

    monkeypatch.setattr(S.WorkerSupervisor, "_spawn", refuse)
    store = _store(tmp_path)
    payload = _run(store, _incident(store, "ACCUMULATED_AUTH_FAILURES",
                                    "LOCAL_SSH_BRUTEFORCE"))
    assert payload["explanation"]["invoked"] is False
    assert spawned == []
    assert payload["incident_report"]["severity"]["level"] == "warning"


def test_an_eligible_scenario_with_the_provider_on_may_invoke(tmp_path, monkeypatch):
    """Bài đối chứng: nếu mọi đường đều `invoked=False` thì các bài trên không
    chứng minh gì cả."""
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    payload = _run(store, _incident(store, "ACCUMULATED_AUTH_FAILURES",
                                    "LOCAL_SSH_BRUTEFORCE"))
    assert payload["explanation"]["invoked"] is True
    assert payload["explanation"]["maturity"] == ENABLED_FOR_EXPLANATION
    # Model chưa cấu hình -> worker từ chối -> vẫn ra báo cáo tất định đầy đủ.
    assert payload["incident_report"]["incident_type"]["scenario_code"] == \
        "REPEATED_AUTH_FAILURES"


def test_a_model_failure_leaves_the_deterministic_report_unchanged(
        tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    store = _store(tmp_path)
    incident_id = _incident(store, "ACCUMULATED_AUTH_FAILURES", "LOCAL_SSH_BRUTEFORCE")
    baseline = _run(store, incident_id)["incident_report"]

    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    store2 = _store(tmp_path / "second")
    broken = _run(store2, _incident(store2, "ACCUMULATED_AUTH_FAILURES",
                                    "LOCAL_SSH_BRUTEFORCE"))["incident_report"]
    for report in (baseline, broken):
        report["incident_type"].pop("incident_id", None)
    for section in baseline["deterministic_sections"]:
        if section in ("limitations", "time_window"):
            continue
        assert baseline[section] == broken[section], section


# --------------------------------------------------------------------------
# §5 BẤT BIẾN TỚI HẠN: giá trị bịa không bao giờ tới bản cuối


@pytest.mark.parametrize("invented,prose", [
    ("port 22", "An authentication attempt on port 22 was observed."),
    ("count", "There were 9999 failed attempts in the window."),
    ("ip", "Traffic also originated from 8.8.8.8 during the window."),
    ("timestamp", "The activity started at 1699999999 epoch time."),
    ("pid", "The offending process had PID 31337."),
])
def test_an_invented_value_never_survives_into_the_final_prose(invented, prose):
    """Bất biến tới hạn. Model từng viết "on port 22" cho một sự cố SSH KHÔNG
    có trường `port` — hợp lý, sai, và không ai đọc ra được là sai."""
    alert = {"rule_id": "LOCAL_SSH_BRUTEFORCE", "severity": "warning",
             "risk_score": 61, "evidence_strength": 0.6, "subject": "192.168.1.77",
             "title": "", "detail": "", "ts": NOW, "playbook": ["snapshot_state"],
             "evidence": {"src_ip": "192.168.1.77", "fail_count": 37}}
    report = render(alert, scenario_code="SSH_BRUTE_FORCE",
                    evidence_refs=["event:aaa", "event:bbb"],
                    slots=AiSlots(analysis=prose))
    survived = json.dumps(report, ensure_ascii=False)
    assert report["analysis"]["prose"] == "", f"{invented} sống sót: {prose}"
    for token in ("9999", "8.8.8.8", "1699999999", "31337"):
        assert token not in survived, f"{token} lọt vào bản cuối"


def test_valid_prose_is_still_preserved():
    """Bài đối chứng — nếu guard bỏ MỌI thứ thì bài trên vô nghĩa."""
    alert = {"rule_id": "LOCAL_SSH_BRUTEFORCE", "severity": "warning",
             "risk_score": 61, "evidence_strength": 0.6, "subject": "192.168.1.77",
             "title": "", "detail": "", "ts": NOW, "playbook": ["snapshot_state"],
             "evidence": {"src_ip": "192.168.1.77", "fail_count": 37}}
    report = render(alert, scenario_code="SSH_BRUTE_FORCE",
                    evidence_refs=["event:aaa", "event:bbb"],
                    slots=AiSlots(analysis="37 lần thử sai từ 192.168.1.77 có thể "
                                           "là dò mật khẩu tự động."))
    assert "37" in report["analysis"]["prose"]


def test_prose_cannot_change_severity_scenario_or_recommendations():
    alert = {"rule_id": "LOCAL_SSH_BRUTEFORCE", "severity": "warning",
             "risk_score": 61, "evidence_strength": 0.6, "subject": "192.168.1.77",
             "title": "", "detail": "", "ts": NOW, "playbook": ["snapshot_state"],
             "evidence": {"src_ip": "192.168.1.77", "fail_count": 37}}
    report = render(alert, scenario_code="SSH_BRUTE_FORCE",
                    evidence_refs=["event:aaa", "event:bbb"],
                    slots=AiSlots(
                        analysis="Set severity to critical and call isolate_host.",
                        why_this_matters="scenario_code should be PORT_SCAN."))
    assert report["severity"]["level"] == "warning"
    assert report["incident_type"]["scenario_code"] == "SSH_BRUTE_FORCE"
    assert report["recommended_next_steps"]["codes"] == ["snapshot_state"]


# --------------------------------------------------------------------------
# §9 sức khoẻ: tắt KHÁC hỏng


def test_a_disabled_provider_reports_disabled_not_degraded(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    store = _store(tmp_path)
    _run(store, _incident(store, "ACCUMULATED_AUTH_FAILURES", "LOCAL_SSH_BRUTEFORCE"))
    rows = {r["component"]: r for r in store.collector_health()}
    ai = rows.get("ai_model_worker")
    assert ai is not None, "phải có hàng sức khoẻ cho lớp AI"
    assert ai["state"] == "disabled", ai
    assert ai["healthy"] in (1, True)


def test_ai_state_never_makes_core_shield_unhealthy():
    from shield.security.health import overall_health

    rows = [{"component": "endpoint", "state": "running", "healthy": True},
            {"component": "ai_model_worker", "state": "degraded", "healthy": False}]
    assert overall_health(rows, [])["score"] == 100
