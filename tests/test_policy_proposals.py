"""Policy tất định, cấu hình đã ký, đề xuất thay vì thực thi (mục 0.3)."""

from __future__ import annotations

import json

import pytest

from shield.security.policy import (
    KNOWN_ACTIONS,
    NEVER_AUTOMATIC,
    PolicyConfig,
    PolicyEngine,
)


# --- mặc định an toàn ---


def test_the_default_engine_is_audit_only():
    engine = PolicyEngine()
    decision = engine.decide("ANY_RULE", 100)
    assert decision.action == "alert" and decision.automatic is False
    assert decision.reason == "policy:audit-only"


def test_audit_only_proposes_nothing_even_at_maximum_risk():
    assert PolicyEngine().propose("ANY_RULE", 100, "snapshot_state", "10.0.0.1") is None


def test_the_old_constructor_still_works():
    """Phần còn lại của agent gọi PolicyEngine(audit_only=True); đổi chữ ký
    lặng lẽ là cách nhanh nhất để mất mặc định an toàn."""
    assert PolicyEngine(audit_only=True).audit_only is True
    assert PolicyEngine(audit_only=False, auto_rules={"R"}).auto_rules == frozenset({"R"})


def test_disabling_audit_only_the_old_way_grants_no_automatic_actions():
    """Cờ cũ chỉ đổi mode; nó không được ngầm cấp quyền chạy action nào."""
    engine = PolicyEngine(audit_only=False, auto_rules={"R"})
    proposal = engine.propose("R", 100, "block_ip", "10.0.0.1")
    assert proposal is not None
    assert proposal.would_be_automatic is False


# --- cấu hình ---


def test_an_unknown_action_is_refused_at_config_time():
    with pytest.raises(ValueError, match="allowlist"):
        PolicyConfig(policy_mode="auto", auto_actions=frozenset({"rm_minus_rf"}))


def test_destructive_actions_can_never_be_configured_as_automatic():
    for action in NEVER_AUTOMATIC:
        with pytest.raises(ValueError, match="không bao giờ"):
            PolicyConfig(policy_mode="auto", auto_actions=frozenset({action}))


def test_an_unknown_config_key_fails_closed():
    """Bỏ qua khoá lạ âm thầm nghĩa là chạy với policy khác cái người ta viết."""
    with pytest.raises(ValueError, match="không nhận ra"):
        PolicyConfig.from_dict({"policy_mode": "audit_only", "auto_contain": True})


@pytest.mark.parametrize("raw", [
    {"policy_mode": "yolo"},
    {"max_ttl_s": 0},
    {"max_ttl_s": 99999},
    {"min_risk_score": 101},
    {"max_actions_per_hour": -1},
])
def test_out_of_range_config_is_refused(raw):
    with pytest.raises(ValueError):
        PolicyConfig.from_dict(raw)


def test_leaving_audit_only_requires_a_signature(tmp_path):
    """Cấu hình phản ứng tự động là thứ kẻ tấn công muốn sửa nhất."""
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"policy_mode": "auto", "auto_rules": ["R"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="đã ký"):
        PolicyConfig.load(path)


def test_audit_only_config_loads_without_a_signature(tmp_path):
    """Không có chữ ký thì vẫn phải chạy được — ở chế độ không làm gì cả."""
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"policy_mode": "audit_only"}), encoding="utf-8")
    assert PolicyConfig.load(path).policy_mode == "audit_only"


def test_a_bad_signature_is_refused(tmp_path):
    payload = tmp_path / "policy.json"
    payload.write_text(json.dumps({"policy_mode": "auto"}), encoding="utf-8")
    (tmp_path / "sig").write_bytes(b"not a signature")
    (tmp_path / "key.pem").write_text("not a key", encoding="utf-8")
    with pytest.raises(ValueError):
        PolicyConfig.load(payload, tmp_path / "key.pem", tmp_path / "sig")


# --- quyết định ---


def _auto_engine(clock=None, **overrides):
    config = PolicyConfig(policy_mode="auto", min_risk_score=85,
                          auto_rules=frozenset({"BRUTE_FORCE"}),
                          auto_actions=frozenset({"snapshot_state"}), **overrides)
    return PolicyEngine(config=config, clock=clock or (lambda: 1000.0))


def test_risk_below_the_threshold_is_not_contained():
    assert _auto_engine().decide("BRUTE_FORCE", 84).reason == "risk:below-auto-threshold"


def test_a_rule_outside_the_allowlist_is_not_contained():
    assert _auto_engine().decide("SOMETHING_ELSE", 100).reason == "rule:not-allowlisted"


def test_recommend_mode_never_marks_a_decision_automatic():
    config = PolicyConfig(policy_mode="recommend", auto_rules=frozenset({"R"}))
    decision = PolicyEngine(config=config).decide("R", 100)
    assert decision.action == "contain" and decision.automatic is False


def test_the_rate_limit_stops_an_alert_storm():
    """Một rule kêu 500 lần không được thành 500 lần chặn."""
    clock = [1000.0]
    engine = _auto_engine(clock=lambda: clock[0], max_actions_per_hour=3)
    automatic = [engine.decide("BRUTE_FORCE", 100).automatic for _ in range(5)]
    assert automatic == [True, True, True, False, False]
    clock[0] += 3601
    assert engine.decide("BRUTE_FORCE", 100).automatic is True


def test_the_rate_limit_counts_across_rules():
    """Kích nhiều rule khác nhau không được là cách lách giới hạn."""
    config = PolicyConfig(policy_mode="auto", auto_rules=frozenset({"A", "B"}),
                          max_actions_per_hour=2)
    engine = PolicyEngine(config=config, clock=lambda: 1000.0)
    assert engine.decide("A", 100).automatic is True
    assert engine.decide("B", 100).automatic is True
    assert engine.decide("A", 100).automatic is False


def test_a_zero_rate_limit_disables_automation_entirely():
    assert _auto_engine(max_actions_per_hour=0).decide("BRUTE_FORCE", 100).automatic is False


# --- đề xuất ---


def test_a_proposal_carries_identity_evidence_and_a_ttl():
    proposal = _auto_engine().propose("BRUTE_FORCE", 100, "snapshot_state", "10.0.0.1",
                                      evidence_refs=("alert:BRUTE_FORCE:10.0.0.1",))
    assert proposal is not None
    assert proposal.proposal_id and proposal.target == "10.0.0.1"
    assert proposal.evidence_refs == ("alert:BRUTE_FORCE:10.0.0.1",)
    assert 0 < proposal.ttl_s <= 3600
    assert proposal.to_dict()["state"] == "PROPOSED"


def test_phase_zero_proposals_always_require_a_human():
    """Tiêu chí Phase 0: policy decision tạo ResponseProposal, CHƯA tự thực thi."""
    proposal = _auto_engine().propose("BRUTE_FORCE", 100, "snapshot_state", "10.0.0.1")
    assert proposal is not None
    assert proposal.requires_human is True
    assert proposal.would_be_automatic is True, "cấu hình cho phép, nhưng vẫn phải chờ người"


def test_an_action_outside_the_source_allowlist_is_never_proposed():
    """Chỗ duy nhất một action ID từ bên ngoài đi vào hệ thống phải đóng."""
    engine = _auto_engine()
    for junk in ("rm -rf /", "block_ip; drop table", "", "BLOCK_IP", "eval"):
        assert engine.propose("BRUTE_FORCE", 100, junk, "10.0.0.1") is None


def test_every_known_action_is_spelled_the_same_as_the_executor_allowlist():
    """Một action ID viết sai chính tả ở đây là một luật policy không bao giờ khớp."""
    assert KNOWN_ACTIONS >= {"alert", "block_ip", "isolate_endpoint", "stop_process"}
