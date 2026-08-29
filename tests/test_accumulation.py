"""Gom log theo SỐ LƯỢNG: đủ nhiều thì phải thành một sự việc được báo cáo.

Một loại log lặp lại bị dedupe thành một alert `warning` là kiểu bỏ sót nguy
hiểm nhất — cuộc dò mật khẩu chậm trông y hệt nhiễu nền.
"""

from __future__ import annotations

import json

import pytest

from shield.common.models import Alert
from shield.security.correlation import (
    MAX_MIN_COUNT,
    CorrelationEngine,
    CorrelationRule,
)

THRESHOLD = CorrelationRule(
    id="ACC_TEST", required_rules=frozenset({"AUTH_FAIL"}),
    window_s=600, min_count=5, title="Repeated auth failures",
)


def alert_at(ts: float, rule_id: str = "AUTH_FAIL", subject: str = "10.0.0.9") -> Alert:
    return Alert(ts, rule_id, "warning", rule_id, "detail", subject)


def test_below_the_threshold_reports_nothing():
    engine = CorrelationEngine([THRESHOLD])
    for i in range(4):
        assert engine.correlate(alert_at(1000 + i)) == []


def test_reaching_the_threshold_opens_an_incident():
    engine = CorrelationEngine([THRESHOLD])
    for i in range(4):
        engine.correlate(alert_at(1000 + i))
    found = engine.correlate(alert_at(1004))
    assert len(found) == 1
    assert found[0].rule.id == "ACC_TEST"
    assert len(found[0].contributing) == 5
    assert found[0].alert.evidence["observed_count"] == 5


def test_events_outside_the_window_do_not_count():
    engine = CorrelationEngine([THRESHOLD])
    for i in range(4):
        engine.correlate(alert_at(1000 + i))
    # Lần thứ 5 đến sau cửa sổ 600s: 4 lần cũ đã hết hạn, không được cộng dồn.
    assert engine.correlate(alert_at(1000 + 700)) == []


def test_a_different_subject_keeps_its_own_count():
    engine = CorrelationEngine([THRESHOLD])
    for i in range(4):
        engine.correlate(alert_at(1000 + i, subject="10.0.0.9"))
    assert engine.correlate(alert_at(1005, subject="10.0.0.10")) == []


def test_an_unrelated_rule_does_not_feed_the_count():
    engine = CorrelationEngine([THRESHOLD])
    for i in range(9):
        engine.correlate(alert_at(1000 + i, rule_id="SOMETHING_ELSE"))
    assert engine.correlate(alert_at(1010)) == []


def test_the_incident_is_throttled_inside_its_window():
    engine = CorrelationEngine([THRESHOLD])
    for i in range(5):
        engine.correlate(alert_at(1000 + i))
    # Cảnh báo lặp lại mỗi lần có thêm một dòng log sẽ chôn vùi chính nó.
    assert engine.correlate(alert_at(1006)) == []
    # Lần bắn đầu ở ts=1004 (dòng thứ 5), nên cửa sổ chặn tính từ đó. Sau khi
    # qua cửa sổ, một đợt mới đủ số lượng phải được báo lại.
    fired = [bool(engine.correlate(alert_at(1700 + i))) for i in range(5)]
    assert fired == [False, False, False, False, True]


def test_history_is_large_enough_for_the_largest_threshold():
    """Ngưỡng cao hơn sức chứa lịch sử = luật không bao giờ khớp, im lặng."""
    big = CorrelationRule(
        id="BIG", required_rules=frozenset({"AUTH_FAIL"}), window_s=600, min_count=300,
    )
    engine = CorrelationEngine([big], max_per_subject=100)
    assert engine.max_per_subject >= 300
    for i in range(299):
        engine.correlate(alert_at(1000 + i))
    assert engine.correlate(alert_at(1299)) != []


def test_subject_tracking_is_bounded():
    """IP nguồn của syslog UDP giả mạo được — bộ nhớ phải có trần."""
    engine = CorrelationEngine([THRESHOLD], max_subjects=64)
    for i in range(5000):
        engine.correlate(alert_at(1000, subject=f"10.1.{i // 256}.{i % 256}"))
    assert len(engine._history) <= 64
    assert len(engine._last_emitted) <= 64
    assert engine.evicted_subjects > 0


def test_a_single_rule_without_a_threshold_is_rejected():
    with pytest.raises(ValueError):
        CorrelationRule.from_dict({"id": "X", "required_rules": ["ONE"]})


def test_an_unreachable_threshold_is_rejected():
    with pytest.raises(ValueError):
        CorrelationRule.from_dict(
            {"id": "X", "required_rules": ["ONE"], "min_count": MAX_MIN_COUNT + 1}
        )
    with pytest.raises(ValueError):
        CorrelationRule.from_dict({"id": "X", "required_rules": ["ONE"], "min_count": 1})


def test_combination_rules_still_work_unchanged():
    combo = CorrelationRule(
        id="COMBO", required_rules=frozenset({"A", "B"}), window_s=600,
    )
    engine = CorrelationEngine([combo])
    assert engine.correlate(alert_at(1000, rule_id="A")) == []
    assert len(engine.correlate(alert_at(1001, rule_id="B"))) == 1


def test_the_shipped_pack_contains_threshold_rules_for_ingested_logs(tmp_path):
    from pathlib import Path

    path = Path("shield/rules/correlation.json")
    rules = CorrelationRule.load_all(path)
    by_id = {rule.id: rule for rule in rules}
    assert by_id["ACCUMULATED_AUTH_FAILURES"].min_count >= 2
    # Log thu từ máy khác cũng phải có đường trở thành sự việc, không chỉ log nội bộ.
    covered = {name for rule in rules for name in rule.required_rules}
    assert {"SYSLOG_AUTH_FAILURE", "PROBE_LOG_GAP"} <= covered


def test_an_unsigned_correlation_pack_is_refused_when_signing_is_on(tmp_path):
    """Sửa được file này là tắt được việc báo cáo sự việc — phải kiểm chữ ký."""
    pack = tmp_path / "correlation.json"
    pack.write_text(json.dumps({
        "schema_version": 1, "pack_type": "correlation",
        "rules": [{"id": "X", "required_rules": ["A", "B"]}],
    }), encoding="utf-8")
    key = tmp_path / "public.pem"
    key.write_text("not a real key", encoding="utf-8")
    assert CorrelationRule.load_all(pack)  # không có khoá thì vẫn nạp được
    with pytest.raises(ValueError, match="chưa được ký"):
        CorrelationRule.load_all(pack, key)
