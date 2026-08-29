"""Thực thể Incident + correlation nạp từ file (mục B5 kế hoạch 1.1)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.common.models import Alert
from shield.security.correlation import CorrelationEngine, CorrelationRule

ROOT = Path(__file__).resolve().parent.parent
CORRELATION_FILE = ROOT / "shield" / "rules" / "correlation.json"


def _alert(rule_id: str, subject: str = "192.0.2.9", ts: float = 1000.0) -> Alert:
    return Alert(ts, rule_id, "warning", "t", "d", subject)


# --- correlation rule từ file ---


def test_the_shipped_correlation_pack_loads():
    rules = CorrelationRule.load_all(CORRELATION_FILE)
    assert len(rules) >= 4, "correlation vẫn chỉ có 1 rule — chưa thoát khỏi mã cứng"
    for rule in rules:
        # Luật ghép cần từ 2 rule; luật ngưỡng chỉ cần 1 rule nhưng phải có min_count.
        assert len(rule.required_rules) >= 2 or rule.min_count >= 2
        assert rule.recommended_action, f"{rule.id} không nói người dùng nên làm gì"


def test_every_correlation_rule_references_rule_ids_that_really_exist():
    """Một correlation trỏ vào rule_id không tồn tại sẽ KHÔNG BAO GIỜ khớp —
    và nó im lặng, nên không ai phát hiện ra là nó chết."""
    detector_ids = set()
    for path in (ROOT / "shield" / "agent" / "detectors").glob("*.py"):
        source = path.read_text()
        import re
        detector_ids |= set(re.findall(r'"([A-Z][A-Z0-9_]{4,})"', source))
    for pack in (ROOT / "shield" / "rules").glob("*.json"):
        data = json.loads(pack.read_text())
        if data.get("pack_type", "event") == "event":
            detector_ids |= {item["id"] for item in data["rules"]}
    detector_ids |= {"ANOMALY_NEW_BEHAVIOR", "ANOMALY_DEVICE_AT_UNUSUAL_TIME",
                     "ANOMALY_LOGIN_AT_UNUSUAL_TIME"}

    for rule in CorrelationRule.load_all(CORRELATION_FILE):
        unknown = rule.required_rules - detector_ids
        assert not unknown, f"{rule.id} trỏ vào rule không tồn tại: {sorted(unknown)}"


def test_a_correlation_rule_needs_at_least_two_components():
    """Một 'correlation' của đúng một rule chỉ là chính rule đó, đội thêm cái tên."""
    with pytest.raises(ValueError):
        CorrelationRule.from_dict({"id": "X", "required_rules": ["ONLY_ONE"], "window_s": 60})


def test_an_absurd_window_is_refused():
    with pytest.raises(ValueError):
        CorrelationRule.from_dict({"id": "X", "required_rules": ["A", "B"], "window_s": 10 ** 9})


def test_an_event_pack_is_not_accepted_as_a_correlation_pack(tmp_path):
    pack = tmp_path / "ssh.json"
    pack.write_text(json.dumps({"schema_version": 1, "rules": []}))
    with pytest.raises(ValueError, match="correlation pack"):
        CorrelationRule.load_all(pack)


# --- engine ---


def _engine() -> CorrelationEngine:
    return CorrelationEngine([CorrelationRule(
        "TEST_CHAIN", frozenset({"A", "B"}), 600.0, "critical",
        "Chuỗi thử", ("T1046",), "Chặn nguồn",
    )])


def test_correlation_only_fires_when_every_component_is_present():
    engine = _engine()
    assert engine.correlate(_alert("A")) == []
    results = engine.correlate(_alert("B", ts=1100.0))
    assert len(results) == 1
    assert results[0].rule.id == "TEST_CHAIN"


def test_components_outside_the_window_do_not_count():
    engine = _engine()
    engine.correlate(_alert("A", ts=1000.0))
    assert engine.correlate(_alert("B", ts=1000.0 + 601)) == []


def test_the_same_chain_does_not_re_fire_within_its_window():
    """Không có chống lặp thì một cuộc tấn công kéo dài sinh ra hàng trăm
    incident giống hệt nhau."""
    engine = _engine()
    engine.correlate(_alert("A"))
    assert len(engine.correlate(_alert("B", ts=1100.0))) == 1
    assert engine.correlate(_alert("B", ts=1200.0)) == []


def test_correlation_carries_mitre_and_a_recommended_action():
    engine = _engine()
    engine.correlate(_alert("A"))
    result = engine.correlate(_alert("B", ts=1100.0))[0]
    assert result.alert.evidence["mitre_techniques"] == ["T1046"]
    assert result.alert.evidence["recommended_action"] == "Chặn nguồn"
    assert {item["rule_id"] for item in result.contributing} == {"A", "B"}


def test_different_subjects_are_never_mixed_together():
    engine = _engine()
    engine.correlate(_alert("A", subject="10.0.0.1"))
    assert engine.correlate(_alert("B", subject="10.0.0.2", ts=1100.0)) == []


# --- lưu trữ incident ---


def test_an_incident_is_created_then_merged(tmp_path):
    """Cùng kiểu tấn công nhắm cùng đối tượng là MỘT sự việc, dù kéo dài cả buổi."""
    store = Store(tmp_path / "shield.db")
    try:
        first = store.open_or_update_incident(
            correlation_id="TEST_CHAIN", subject="10.0.0.9", title="Chuỗi thử",
            severity="critical", risk_score=70, evidence_strength=0.8,
            mitre_techniques=["T1046"], recommended_action="Chặn nguồn",
            contributing=[{"rule_id": "A", "ts": 1000.0}, {"rule_id": "B", "ts": 1100.0}],
        )
        second = store.open_or_update_incident(
            correlation_id="TEST_CHAIN", subject="10.0.0.9", title="Chuỗi thử",
            severity="critical", risk_score=90, evidence_strength=0.9,
            contributing=[{"rule_id": "A", "ts": 1200.0}],
        )
        assert first["incident_id"] == second["incident_id"]
        incidents = store.list_incidents()
        assert len(incidents) == 1
        assert incidents[0]["risk_score"] == 90
        assert incidents[0]["alert_count"] == 3
        assert store.incident_alerts(first["incident_id"])
    finally:
        store.close()


def test_a_recurrence_after_closing_opens_a_new_incident(tmp_path):
    """Nếu gộp vào incident đã đóng, dòng thời gian của hai đợt tấn công khác
    nhau sẽ dính vào nhau và không tách ra được nữa."""
    store = Store(tmp_path / "shield.db")
    try:
        first = store.open_or_update_incident(
            correlation_id="TEST_CHAIN", subject="10.0.0.9", title="t",
            severity="critical", contributing=[{"rule_id": "A", "ts": 1.0}],
        )
        assert store.set_incident_state(first["incident_id"], "resolved") is True
        second = store.open_or_update_incident(
            correlation_id="TEST_CHAIN", subject="10.0.0.9", title="t",
            severity="critical", contributing=[{"rule_id": "A", "ts": 2.0}],
        )
        assert first["incident_id"] != second["incident_id"]
        assert len(store.list_incidents()) == 2
        assert len(store.list_incidents(include_closed=False)) == 1
    finally:
        store.close()


def test_different_subjects_get_different_incidents(tmp_path):
    store = Store(tmp_path / "shield.db")
    try:
        a = store.open_or_update_incident(correlation_id="C", subject="10.0.0.1",
                                          title="t", severity="warning")
        b = store.open_or_update_incident(correlation_id="C", subject="10.0.0.2",
                                          title="t", severity="warning")
        assert a["incident_id"] != b["incident_id"]
    finally:
        store.close()


def test_an_invalid_incident_state_is_refused(tmp_path):
    store = Store(tmp_path / "shield.db")
    try:
        incident = store.open_or_update_incident(correlation_id="C", subject="s",
                                                 title="t", severity="info")
        with pytest.raises(ValueError):
            store.set_incident_state(incident["incident_id"], "đã xong rồi")
    finally:
        store.close()


def test_incidents_are_ranked_by_risk_not_by_time(tmp_path):
    """Người dùng cần thấy việc NGHIÊM TRỌNG nhất trước, không phải việc mới nhất."""
    store = Store(tmp_path / "shield.db")
    try:
        store.open_or_update_incident(correlation_id="LOW", subject="s1", title="t",
                                      severity="warning", risk_score=30)
        time.sleep(0.01)
        store.open_or_update_incident(correlation_id="HIGH", subject="s2", title="t",
                                      severity="critical", risk_score=95)
        assert store.list_incidents()[0]["correlation_id"] == "HIGH"
    finally:
        store.close()
