"""Risk = Severity x Confidence x Asset Value x Repetition x Threat Context.

Kiểm hai thứ tách biệt: công thức (thuần tuý, không cần DB) và việc đọc ngữ
cảnh từ store (cần DB tạm, không chạm mạng).
"""

from __future__ import annotations

import time
from dataclasses import replace

from shield.agent.store import Store
from shield.common.models import Alert
from shield.security.scoring import RiskContext, RiskScorer, repetition_weight


def _alert(**changes) -> Alert:
    base = Alert(
        ts=1.0, rule_id="LOCAL_SSH_BRUTEFORCE", severity="warning",
        title="t", detail="d", subject="192.0.2.50",
        evidence={"ip": "192.0.2.50", "attempts": 20, "user": "root"},
    )
    return replace(base, **changes)


def test_scoring_is_deterministic():
    """Cam kết trong docstring của module: cùng input luôn ra cùng điểm."""
    scorer = RiskScorer()
    context = RiskContext(asset_criticality="Critical", repetition=12, threat_verdict="malicious")
    results = {scorer.assess(_alert(), context).score for _ in range(20)}
    assert len(results) == 1


def test_a_critical_asset_scores_higher_than_a_low_priority_one():
    scorer = RiskScorer()
    critical = scorer.assess(_alert(), RiskContext(asset_criticality="Critical"))
    normal = scorer.assess(_alert(), RiskContext(asset_criticality="Normal"))
    low = scorer.assess(_alert(), RiskContext(asset_criticality="Low priority"))
    assert critical.score > normal.score > low.score
    assert "asset:Critical" in critical.reasons


def test_repetition_raises_the_score_in_bands():
    scorer = RiskScorer()
    once = scorer.assess(_alert(), RiskContext(repetition=1))
    many = scorer.assess(_alert(), RiskContext(repetition=25))
    assert many.score > once.score
    assert repetition_weight(1) == 1.0 < repetition_weight(5) < repetition_weight(20)


def test_threat_intel_moves_the_score_both_ways():
    scorer = RiskScorer()
    malicious = scorer.assess(_alert(), RiskContext(threat_verdict="malicious"))
    unknown = scorer.assess(_alert(), RiskContext(threat_verdict="unknown"))
    clean = scorer.assess(_alert(), RiskContext(threat_verdict="clean"))
    assert malicious.score > unknown.score > clean.score


def test_intel_corroboration_raises_confidence_not_only_score():
    scorer = RiskScorer()
    plain = scorer.assess(_alert())
    corroborated = scorer.assess(
        _alert(), RiskContext(threat_verdict="malicious", threat_confidence=1.0)
    )
    assert corroborated.confidence > plain.confidence


def test_trusted_subject_still_lowers_the_score():
    scorer = RiskScorer()
    assert scorer.assess(_alert(), RiskContext(trusted=True)).score < scorer.assess(_alert()).score
    # Đường cũ qua evidence vẫn phải chạy, detector hiện có đang dùng nó.
    assert scorer.assess(_alert(evidence={"trusted": True})).score < scorer.assess(_alert()).score


def test_score_stays_inside_zero_to_hundred_under_every_multiplier():
    scorer = RiskScorer()
    worst = scorer.assess(
        _alert(severity="critical", rule_id="MITM_MALWARE_INTEGRITY"),
        RiskContext(asset_criticality="Critical", repetition=10_000,
                    threat_verdict="malicious", threat_confidence=1.0),
    )
    assert 0 <= worst.score <= 100
    assert 0.0 <= worst.confidence <= 0.98


def test_no_context_keeps_the_pre_1_1_behaviour():
    """Alert phát ra trước khi thiết bị được nhận diện phải chấm đúng như cũ,
    nếu không mọi điểm rủi ro trong lịch sử đột nhiên lệch chuẩn."""
    scorer = RiskScorer()
    assert scorer.assess(_alert()).score == scorer.assess(_alert(), RiskContext()).score


def test_reasons_explain_every_factor_that_moved_the_score():
    """Điểm không giải thích được thì người dùng không tin — và không nên tin."""
    result = RiskScorer().assess(
        _alert(), RiskContext(asset_criticality="Critical", repetition=25,
                              threat_verdict="malicious", threat_confidence=0.9),
    )
    joined = " ".join(result.reasons)
    for token in ("severity:", "asset:", "repetition:", "threat-intel:"):
        assert token in joined
    assert set(result.factors) == {"base", "asset", "repetition", "threat", "trust"}


# --- đọc ngữ cảnh từ store ---


def test_risk_context_reads_asset_criticality_and_trust(tmp_path):
    store = Store(tmp_path / "shield.db")
    store.upsert_device("aa:bb:cc:dd:ee:ff", "192.0.2.50", "Vendor", {"hostname": "host"})
    identities = store.list_device_identities()
    assert identities, "upsert_device phải tạo device identity"
    store.update_device_metadata(identities[0]["device_id"], display_name="Máy chủ NAS",
                                 criticality="Critical")
    store.add_trusted("aa:bb:cc:dd:ee:ff")

    by_ip = store.risk_context("192.0.2.50")
    assert by_ip["asset_criticality"] == "Critical"
    assert by_ip["trusted"] is True
    assert store.risk_context("aa:bb:cc:dd:ee:ff")["asset_criticality"] == "Critical"
    store.close()


def test_risk_context_reads_repetition_and_threat_intel(tmp_path):
    store = Store(tmp_path / "shield.db")
    for _ in range(6):
        store.insert_alert(_alert(ts=time.time()), dedupe_window_s=3600)
    store.put_threat_intel_cache("ip", "192.0.2.50", "static", "malicious",
                                 {"confidence": 0.9}, ttl_s=600)
    context = store.risk_context("192.0.2.50")
    assert context["repetition"] >= 5
    assert context["threat_verdict"] == "malicious"
    assert context["threat_confidence"] == 0.9
    store.close()


def test_expired_threat_intel_is_ignored(tmp_path):
    """Verdict hết hạn phải bị bỏ qua — nếu không, một IP từng bị đánh dấu
    xấu sẽ kéo điểm rủi ro lên mãi mãi kể cả sau khi nó đã sạch."""
    store = Store(tmp_path / "shield.db")
    store.conn.execute(
        "INSERT OR REPLACE INTO threat_intel_cache"
        "(indicator_type,indicator,provider,verdict,payload,expires_ts) VALUES(?,?,?,?,?,?)",
        ("ip", "192.0.2.50", "static", "malicious", '{"confidence": 1.0}', time.time() - 1),
    )
    store.conn.commit()
    assert store.risk_context("192.0.2.50")["threat_verdict"] == "unknown"
    store.close()


def test_risk_context_never_raises_on_an_unknown_subject(tmp_path):
    """Subject có thể là behavior_key hoặc chuỗi lạ. Chấm điểm không được đứt."""
    store = Store(tmp_path / "shield.db")
    for subject in ("", "   ", "process_exec|root|2|/usr/bin/curl", "không-phải-ip"):
        context = store.risk_context(subject)
        assert context["asset_criticality"] == "Normal"
        assert context["repetition"] == 1
    store.close()
