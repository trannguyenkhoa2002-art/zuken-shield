from dataclasses import replace

from shield.common.models import Alert
from shield.security import PolicyEngine, RiskScorer


def _alert(**changes):
    base = Alert(
        ts=1.0, rule_id="MITM_GATEWAY_MAC_CHANGED", severity="critical",
        title="test", detail="test", subject="192.0.2.1",
        evidence={"old_mac": "a", "new_mac": "b", "ip": "192.0.2.1"},
    )
    return replace(base, **changes)


def test_high_signal_critical_alert_scores_high():
    result = RiskScorer().assess(_alert())
    assert 90 <= result.score <= 100
    assert result.confidence > 0.5


def test_trusted_subject_reduces_score():
    normal = RiskScorer().assess(_alert())
    trusted = RiskScorer().assess(_alert(evidence={"trusted": True}))
    assert trusted.score < normal.score


def test_policy_is_audit_only_by_default():
    decision = PolicyEngine().decide("MITM_GATEWAY_MAC_CHANGED", 100)
    assert decision.action == "alert"
    assert not decision.automatic


def test_auto_response_requires_threshold_and_allowlist():
    policy = PolicyEngine(audit_only=False, auto_rules={"RULE_A"})
    assert policy.decide("RULE_A", 84).action == "alert"
    assert policy.decide("RULE_B", 99).action == "alert"
    assert policy.decide("RULE_A", 90).action == "contain"
