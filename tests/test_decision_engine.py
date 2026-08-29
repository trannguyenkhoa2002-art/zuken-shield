"""Phase 3: tách điểm số, hiệu chuẩn, và quyết định tất định.

KE-HOACH-SHIELD-2.0.md mục 3.1, 3.3. Gate của phase:

- Decision replay cho cùng input/config luôn ra cùng kết quả.
- Không có đường từ AI prose tới command execution.
- Mọi auto action có TTL, rate limit, target identity và rollback plan.
- Policy downgrade/deny được audit rõ lý do.
"""

from __future__ import annotations

import sqlite3

import pytest

from shield.agent.store import Store
from shield.common.models import Alert
from shield.decision.calibration import (
    CALIBRATION_SCHEMA,
    MIN_SAMPLES,
    CalibrationRecord,
    DetectorCalibration,
)
from shield.decision.models import (
    ACTION_SPECS,
    MAX_AUTOMATIC_LEVEL,
    build_decision,
    decision_id_for,
)
from shield.security.policy import PolicyConfig, PolicyEngine
from shield.security.scoring import RiskScorer


# --- 3.1 tách khái niệm điểm số ---


def test_evidence_strength_is_not_called_confidence_any_more():
    """Người đọc thấy "confidence 0.90" và hiểu "90% khả năng đúng"; thực tế nó
    chỉ có nghĩa "alert này có 5 mẩu bằng chứng"."""
    assessment = RiskScorer().assess(Alert(1.0, "R", "warning", "t", "d", "s"))
    assert hasattr(assessment, "evidence_strength")
    assert assessment.confidence == assessment.evidence_strength


def test_an_uncalibrated_detector_has_unknown_precision_not_a_default():
    """Điền 0.5 hay 0.9 vào đó là bịa ra một con số rồi để người khác quyết
    định dựa trên nó."""
    assessment = RiskScorer().assess(Alert(1.0, "R", "warning", "t", "d", "s"))
    assert assessment.detector_precision is None


def test_evidence_strength_and_detector_precision_are_independent(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    calibration = DetectorCalibration(store.conn)
    for _ in range(MIN_SAMPLES):
        calibration.record_label("NOISY_RULE", "false_positive")
    store.conn.commit()

    scorer = RiskScorer(calibration)
    # Alert nhiều bằng chứng -> evidence_strength CAO...
    rich = Alert(1.0, "NOISY_RULE", "critical", "t", "d", "s",
                 evidence={"a": 1, "b": 2, "c": 3, "d": 4, "e": 5})
    assessment = scorer.assess(rich)
    assert assessment.evidence_strength > 0.8
    # ...nhưng detector này chưa từng đúng lần nào.
    assert assessment.detector_precision == 0.0


def test_a_scoring_failure_in_calibration_never_breaks_scoring():
    class Broken:
        def precision_for(self, rule_id):
            raise RuntimeError("bảng hỏng")

    assessment = RiskScorer(Broken()).assess(Alert(1.0, "R", "warning", "t", "d", "s"))
    assert assessment.score > 0
    assert assessment.detector_precision is None


# --- hiệu chuẩn ---


@pytest.fixture()
def calibration():
    conn = sqlite3.connect(":memory:")
    conn.executescript(CALIBRATION_SCHEMA)
    return DetectorCalibration(conn)


def test_precision_is_none_until_there_are_enough_samples(calibration):
    """Ba mẫu đúng liên tiếp cho ra 100% — vừa đúng về số học vừa vô nghĩa về
    thống kê."""
    for _ in range(MIN_SAMPLES - 1):
        calibration.record_label("R", "true_positive")
    assert calibration.precision_for("R") is None
    calibration.record_label("R", "true_positive")
    assert calibration.precision_for("R") == 1.0


def test_undetermined_labels_do_not_punish_the_detector(calibration):
    """Gộp 'chưa rõ' vào false_positive sẽ phạt oan; bỏ đi thì mất dấu vết
    rằng có những alert không ai hiểu."""
    for _ in range(MIN_SAMPLES):
        calibration.record_label("R", "true_positive")
    for _ in range(50):
        calibration.record_label("R", "undetermined")
    assert calibration.precision_for("R") == 1.0
    assert calibration.get("R").undetermined == 50


def test_a_confidence_interval_exposes_a_small_sample(calibration):
    """19/20 và 950/1000 đều ra 95%, nhưng cái đầu có thể là 75% thực tế."""
    for _ in range(19):
        calibration.record_label("SMALL", "true_positive")
    calibration.record_label("SMALL", "false_positive")
    low, high = calibration.get("SMALL").interval()
    assert low < 0.85, f"khoảng tin cậy quá hẹp cho 20 mẫu: {low}"

    big = CalibrationRecord("BIG", true_positives=950, false_positives=50)
    big_low, _ = big.interval()
    assert big_low > low, "1000 mẫu phải cho khoảng chặt hơn 20 mẫu"


def test_versions_are_calibrated_separately(calibration):
    for _ in range(MIN_SAMPLES):
        calibration.record_label("R", "true_positive", detector_version="v1")
        calibration.record_label("R", "false_positive", detector_version="v2")
    assert calibration.precision_for("R", "v1") == 1.0
    assert calibration.precision_for("R", "v2") == 0.0


def test_only_the_three_human_labels_are_accepted(calibration):
    """Không có đường nào cho detector tự dán nhãn cho chính nó, và cũng không
    có đường nào cho AI. Một hệ thống tự chấm điểm mình luôn được điểm cao."""
    for junk in ("probably_true", "auto", "", "true", None, "TRUE_POSITIVE"):
        with pytest.raises(ValueError):
            calibration.record_label("R", junk)


# --- 3.3 quyết định tất định ---


def _auto_engine(**overrides):
    config = PolicyConfig(policy_mode="auto", min_risk_score=80,
                          auto_rules=frozenset({"R"}),
                          auto_actions=frozenset({"block_ip"}), **overrides)
    return PolicyEngine(config=config, clock=lambda: 1000.0)


def test_replaying_a_decision_gives_the_same_id():
    """Gate: decision replay cho cùng input/config luôn ra cùng kết quả."""
    first = build_decision("inc", "block_ip", {"ip": "10.0.0.5"}, policy_rule_id="R",
                           evidence_refs=["event:b", "event:a"], mode="auto",
                           ttl_s=300, requires_human=False)
    second = build_decision("inc", "block_ip", {"ip": "10.0.0.5"}, policy_rule_id="R",
                            evidence_refs=["event:a", "event:b", "event:a"], mode="auto",
                            ttl_s=300, requires_human=False)
    assert first.decision_id == second.decision_id
    assert first.to_dict() == second.to_dict()


def test_a_decision_id_is_not_random():
    """uuid4 nghĩa là mỗi lần chạy ra một ID mới, và 'phát lại quyết định'
    không đối chiếu được với bản ghi cũ."""
    ids = {decision_id_for("inc", "block_ip", {"ip": "1.2.3.4"}, "R", ["event:a"])
           for _ in range(20)}
    assert len(ids) == 1


def test_a_different_target_gives_a_different_decision():
    a = decision_id_for("inc", "block_ip", {"ip": "10.0.0.5"}, "R", ["event:a"])
    b = decision_id_for("inc", "block_ip", {"ip": "10.0.0.6"}, "R", ["event:a"])
    assert a != b


def test_every_action_spec_has_a_rollback_plan():
    """Mục 4.2: không thêm action mới nếu thiếu verify() và rollback(); ngoại
    lệ phá huỷ phải ghi rõ không đảo ngược và luôn human-only."""
    for action, spec in ACTION_SPECS.items():
        assert spec["rollback"], action
        assert spec["rollback"]["reason"], action
        if not spec["reversible"]:
            assert spec["level"] > MAX_AUTOMATIC_LEVEL, \
                f"{action} không đảo ngược được nhưng lại nằm trong mức tự động"


def test_every_timed_action_must_carry_a_positive_ttl():
    """Một action có TTL mà TTL bằng 0 nghĩa là chặn vĩnh viễn."""
    with pytest.raises(ValueError, match="TTL"):
        build_decision("inc", "block_ip", {"ip": "1.2.3.4"}, policy_rule_id="R",
                       evidence_refs=["event:a"], mode="auto", ttl_s=0,
                       requires_human=False)


def test_the_ttl_is_capped_by_the_action_spec_not_by_config():
    decision = build_decision("inc", "block_ip", {"ip": "1.2.3.4"}, policy_rule_id="R",
                              evidence_refs=["event:a"], mode="auto", ttl_s=10 ** 6,
                              requires_human=False)
    assert decision.ttl_s == ACTION_SPECS["block_ip"]["max_ttl_s"]


def test_a_destructive_action_always_requires_a_human():
    decision = build_decision("inc", "stop_process", {"pid": 9}, policy_rule_id="R",
                              evidence_refs=["event:a"], mode="auto", ttl_s=0,
                              requires_human=False)
    assert decision.requires_human is True


def test_containment_always_requires_a_human_at_2_0():
    decision = build_decision("inc", "isolate_endpoint", {"ip": "10.0.0.1"},
                              policy_rule_id="R", evidence_refs=["event:a"],
                              mode="auto", ttl_s=300, requires_human=False)
    assert decision.level > MAX_AUTOMATIC_LEVEL
    assert decision.requires_human is True


def test_an_unknown_action_cannot_be_built():
    for junk in ("rm -rf /", "BLOCK_IP", "", "block_ip; drop"):
        with pytest.raises(ValueError):
            build_decision("inc", junk, {}, policy_rule_id="R",
                           evidence_refs=["event:a"], mode="auto", ttl_s=60,
                           requires_human=False)


# --- từ chối cũng phải được ghi ---


def test_a_decision_without_evidence_is_denied_with_a_reason():
    outcome = _auto_engine().decide_action("inc", "R", 100, "block_ip",
                                           {"ip": "1.2.3.4"}, [])
    assert outcome.decision is None
    assert "bằng chứng" in outcome.denied_reason


def test_a_denied_decision_records_what_was_evaluated():
    """Một hệ thống chỉ ghi những lần nó hành động sẽ không trả lời được câu
    hỏi quan trọng nhất sau một sự cố: vì sao lúc đó nó KHÔNG làm gì."""
    outcome = _auto_engine().decide_action("inc", "R", 100, "khong_ton_tai",
                                           {"ip": "1.2.3.4"}, ["event:a"])
    assert outcome.decision is None
    assert outcome.denied_reason
    assert outcome.evaluated["risk_score"] == 100
    assert outcome.evaluated["policy_mode"] == "auto"


def test_low_risk_is_downgraded_to_recommend_with_a_reason():
    outcome = _auto_engine().decide_action("inc", "R", 10, "block_ip",
                                           {"ip": "1.2.3.4"}, ["event:a"])
    assert outcome.decision.mode == "recommend"
    assert outcome.decision.requires_human is True
    assert outcome.decision.downgrade_reason


def test_an_uncalibrated_detector_cannot_act_automatically():
    """Không biết một detector đúng bao nhiêu phần trăm mà vẫn cho nó tự hành
    động là đánh cược bằng hệ thống của người khác."""
    outcome = _auto_engine().decide_action("inc", "R", 100, "block_ip",
                                           {"ip": "1.2.3.4"}, ["event:a"],
                                           detector_precision=None)
    assert outcome.decision.mode == "recommend"
    assert "hiệu chuẩn" in outcome.decision.downgrade_reason


def test_a_calibrated_allowlisted_action_can_be_automatic():
    outcome = _auto_engine().decide_action("inc", "R", 100, "block_ip",
                                           {"ip": "1.2.3.4"}, ["event:a"],
                                           detector_precision=0.95)
    assert outcome.decision.mode == "auto"
    assert outcome.decision.requires_human is False
    assert outcome.decision.ttl_s > 0
    assert outcome.decision.rollback_plan["action"] == "unblock_ip"


def test_an_action_outside_the_signed_config_stays_recommend():
    outcome = _auto_engine().decide_action("inc", "R", 100, "snapshot_state",
                                           {}, ["event:a"], detector_precision=0.99)
    assert outcome.decision.mode == "recommend"
    assert "cấp phép" in outcome.decision.downgrade_reason


def test_audit_only_never_produces_an_auto_decision():
    outcome = PolicyEngine().decide_action("inc", "R", 100, "block_ip",
                                           {"ip": "1.2.3.4"}, ["event:a"],
                                           detector_precision=0.99)
    assert outcome.decision.mode == "recommend"
    assert outcome.decision.downgrade_reason == "policy:audit-only"


# --- không có đường từ văn xuôi tới lệnh ---


def test_no_decision_field_can_carry_free_text_into_execution():
    """Gate: không có đường từ AI prose tới command execution.

    Mọi trường quyết định phải là ID, số, hoặc cấu trúc tra từ ACTION_SPECS —
    không trường nào là câu tự do đi thẳng tới chỗ chạy lệnh.
    """
    decision = build_decision("inc", "block_ip", {"ip": "1.2.3.4"}, policy_rule_id="R",
                              evidence_refs=["event:a"], mode="auto", ttl_s=60,
                              requires_human=False)
    spec = ACTION_SPECS["block_ip"]
    assert decision.rollback_plan == spec["rollback"]
    assert decision.preconditions == tuple(spec["preconditions"])
    assert decision.blast_radius == spec["blast_radius"]
    # `reason` là text, nhưng nó chỉ đi vào audit — không có adapter nào đọc nó.
    assert isinstance(decision.reason, str)


def test_the_recommendable_actions_are_a_subset_of_the_action_specs():
    from shield.ai.contracts import RECOMMENDABLE_ACTIONS

    assert RECOMMENDABLE_ACTIONS <= set(ACTION_SPECS)


# --- 3.1 (tiếp): con số cuối cùng còn nói dối ---


def test_the_alert_field_is_named_for_what_it_measures():
    """`Alert.confidence` đọc như "khả năng đúng"; nó có nghĩa "có bao nhiêu mẩu
    bằng chứng". Hai câu hỏi khác nhau."""
    from shield.common.models import Alert as _Alert

    assert "evidence_strength" in _Alert.__dataclass_fields__
    assert "confidence" not in _Alert.__dataclass_fields__


def test_the_old_name_still_reads_the_same_number():
    """Đổi tên VÀ đổi ngữ nghĩa trong một lượt là cách chắc chắn để không ai
    biết chỗ nào đã sửa."""
    alert = Alert(1.0, "R", "warning", "t", "d", "s", evidence_strength=0.83)
    assert alert.confidence == 0.83


def test_an_alert_saved_before_2_0_still_loads():
    """Một bản ghi cũ không đọc được là một bản ghi mất."""
    from shield.common.models import Alert as _Alert

    legacy = {"ts": 1.0, "rule_id": "R", "severity": "warning", "title": "t",
              "detail": "d", "subject": "s", "confidence": 0.77}
    assert _Alert.from_dict(legacy).evidence_strength == 0.77


def test_the_serialised_form_carries_both_names(tmp_path):
    """Cột/khoá cũ là GƯƠNG cho bản trước, không phải một con số độc lập có
    thể lệch."""
    payload = Alert(1.0, "R", "warning", "t", "d", "s", evidence_strength=0.42).to_dict()
    assert payload["evidence_strength"] == payload["confidence"] == 0.42


def test_the_database_keeps_both_columns_in_step(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    try:
        store.insert_alert(Alert(1.0, "R", "warning", "t", "d", "s",
                                 evidence_strength=0.91))
        row = store.conn.execute(
            "SELECT confidence, evidence_strength FROM alerts").fetchone()
        assert row == (0.91, 0.91)
    finally:
        store.close()


def test_migrating_an_old_database_copies_the_value_across(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    store = Store(path, allow_migration=True)
    store.insert_alert(Alert(1.0, "R", "warning", "t", "d", "s", evidence_strength=0.65))
    store.close()

    # Giả lập database trước 2.0: chỉ có cột cũ.
    conn = sqlite3.connect(path)
    conn.execute("UPDATE alerts SET evidence_strength=0.5")
    conn.execute("PRAGMA user_version=6")
    conn.commit()
    conn.close()

    migrated = Store(path, allow_migration=True)
    try:
        assert migrated.conn.execute(
            "SELECT evidence_strength FROM alerts").fetchone()[0] == 0.65
    finally:
        migrated.close()


def test_incidents_use_the_same_name(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    try:
        store.open_or_update_incident(
            correlation_id="C", subject="host", title="t", severity="warning",
            risk_score=50, evidence_strength=0.72)
        row = store.conn.execute(
            "SELECT confidence, evidence_strength FROM incidents").fetchone()
        assert row == (0.72, 0.72)
    finally:
        store.close()
