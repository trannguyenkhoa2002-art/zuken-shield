import json

import pytest

from shield.common.models import Alert, Event
from shield.security.correlation import CorrelationEngine, CorrelationRule
from shield.security.rules import EventRule, RuleDetector


def rule_dict():
    return {
        "id": "TEST_TMP", "version": 1, "kind": "process_started", "source": "endpoint",
        "match": {"field": "exe", "operator": "prefix", "value": "/tmp/"},
        "severity": "warning", "title": "tmp", "detail": "PID {pid}: {exe}",
        "subject_field": "exe", "playbook": ["snapshot_state"],
    }


def test_declarative_rule_matches_and_carries_version():
    detector = RuleDetector([EventRule.from_dict(rule_dict())])
    alerts = detector.handle_event(Event(1.0, "endpoint", "process_started", {"pid": 7, "exe": "/tmp/x"}))
    assert alerts[0].rule_id == "TEST_TMP"
    assert alerts[0].evidence["rule_version"] == 1


def test_rule_rejects_unknown_operator():
    raw = rule_dict()
    raw["match"]["operator"] = "python_eval"
    with pytest.raises(ValueError, match="unsupported operator"):
        EventRule.from_dict(raw)


def test_rule_file_schema_and_disabled_rules(tmp_path):
    path = tmp_path / "rules.json"
    disabled = rule_dict()
    disabled["enabled"] = False
    path.write_text(json.dumps({"schema_version": 1, "rules": [disabled]}))
    assert RuleDetector.from_file(path).rules == ()


def make_alert(ts, rule_id, subject="192.0.2.4"):
    return Alert(ts, rule_id, "warning", "title", "detail", subject)


def test_correlation_requires_all_rules_same_subject_in_window():
    engine = CorrelationEngine([
        CorrelationRule("CORR", frozenset({"A", "B"}), 60),
    ])
    assert engine.handle_alert(make_alert(100, "A")) == []
    result = engine.handle_alert(make_alert(120, "B"))
    assert result[0].rule_id == "CORR"
    assert result[0].severity == "critical"


def test_correlation_does_not_mix_subjects_or_repeat_in_window():
    engine = CorrelationEngine([CorrelationRule("CORR", frozenset({"A", "B"}), 60)])
    engine.handle_alert(make_alert(100, "A", "one"))
    assert engine.handle_alert(make_alert(110, "B", "two")) == []
    assert engine.handle_alert(make_alert(120, "B", "one"))
    assert engine.handle_alert(make_alert(130, "A", "one")) == []


# --- rule pack theo lĩnh vực (mục B4 kế hoạch 1.1) ---

import json as _json
from pathlib import Path as _Path

import pytest as _pytest

from shield.common.models import Event as _Event
from shield.security.rules import (
    ALLOWED_OPERATORS,
    MAX_REGEX_PATTERN_CHARS,
)

_RULE_DIR = _Path(__file__).resolve().parent.parent / "shield" / "rules"


def test_every_shipped_rule_pack_loads():
    detector = RuleDetector.from_directory(_RULE_DIR)
    assert len(detector.rules) >= 10, "rule pack bị rỗng — hạ tầng có mà nội dung không"
    packs = list(_RULE_DIR.glob("*.json"))
    assert len(packs) >= 4, "rule phải tách theo lĩnh vực, không dồn vào một file"


def test_rule_ids_are_unique_across_every_pack():
    """Trùng id giữa hai pack nghĩa là một alert có hai định nghĩa khác nhau —
    và người dùng không biết cái nào đã bắn."""
    seen = set()
    for pack in _RULE_DIR.glob("*.json"):
        for item in _json.loads(pack.read_text())["rules"]:
            assert item["id"] not in seen, f"id trùng: {item['id']}"
            seen.add(item["id"])


def test_loading_the_directory_refuses_an_unsigned_pack(tmp_path):
    """Bỏ qua pack chưa ký là vô hiệu hoá cả cơ chế ký: kẻ tấn công chỉ cần
    thả một file .json mới vào thư mục."""
    (tmp_path / "a.json").write_text(_json.dumps({"schema_version": 1, "rules": []}))
    with _pytest.raises(ValueError, match="chưa được ký"):
        RuleDetector.from_directory(tmp_path, public_key=tmp_path / "khoá.pem")


def test_new_operators_behave():
    def rule(operator, value, field="port"):
        return EventRule.from_dict({
            "id": "T", "version": 1, "kind": "k", "severity": "info",
            "title": "t", "detail": "d", "subject_field": field,
            "match": {"field": field, "operator": operator, "value": value},
        })

    event = _Event(ts=1.0, source="s", kind="k", data={"port": 3389, "name": "sshd"})
    assert rule("gte", 1024).matches(event)
    assert not rule("gte", 9000).matches(event)
    assert rule("lte", 9000).matches(event)
    assert rule("in", [22, 3389]).matches(event)
    assert rule("not_in", [22, 80]).matches(event)
    assert rule("ne", 22).matches(event)
    assert rule("exists", True).matches(event)
    assert not rule("exists", True, field="thiếu").matches(event)
    assert rule("regex", "^ssh", field="name").matches(event)


def test_a_boolean_is_never_compared_as_a_number():
    """bool là con của int trong Python — `enabled: true >= 1` sẽ đúng và cho
    ra một kết quả hoàn toàn vô nghĩa."""
    rule = EventRule.from_dict({
        "id": "T", "version": 1, "kind": "k", "severity": "info",
        "title": "t", "detail": "d", "subject_field": "flag",
        "match": {"field": "flag", "operator": "gte", "value": 1},
    })
    assert not rule.matches(_Event(ts=1.0, source="s", kind="k", data={"flag": True}))


def test_a_broken_regex_is_rejected_at_load_time_not_at_match_time():
    """Rule hỏng phải chết lúc nạp, chứ không phải lúc đang có tấn công."""
    with _pytest.raises(ValueError):
        EventRule.from_dict({
            "id": "T", "version": 1, "kind": "k", "severity": "info",
            "title": "t", "detail": "d", "subject_field": "m",
            "match": {"field": "m", "operator": "regex", "value": "([unclosed"},
        })


def test_an_overlong_regex_pattern_is_refused():
    with _pytest.raises(ValueError):
        EventRule.from_dict({
            "id": "T", "version": 1, "kind": "k", "severity": "info",
            "title": "t", "detail": "d", "subject_field": "m",
            "match": {"field": "m", "operator": "regex",
                      "value": "a" * (MAX_REGEX_PATTERN_CHARS + 1)},
        })


def test_a_catastrophic_backtracking_pattern_is_refused_at_load_time():
    """Cắt độ dài đầu vào KHÔNG cứu được: `(a+)+b` gặp 2000 ký tự "a" vẫn treo,
    vì backtracking bùng nổ theo hàm mũ chứ không theo độ dài. Phải chặn từ
    hình dạng pattern lúc nạp."""
    for pattern in ("(a+)+b", "(a*)*b", "(?:x+)+y", "(ab+){2,}c"):
        with _pytest.raises(ValueError, match="quantifier"):
            EventRule.from_dict({
                "id": "T", "version": 1, "kind": "k", "severity": "info",
                "title": "t", "detail": "d", "subject_field": "m",
                "match": {"field": "m", "operator": "regex", "value": pattern},
            })


def test_ordinary_patterns_still_load():
    """Heuristic bảo thủ thì phải kiểm cả chiều ngược: nếu nó từ chối luôn
    những pattern bình thường thì rule pack không viết được nữa."""
    for pattern in ("(?i)(authentication fail|login failed)", "^ssh", r"\bport \d+\b",
                    "(?i)(system (restart|reboot)|cold start)"):
        rule = EventRule.from_dict({
            "id": "T", "version": 1, "kind": "k", "severity": "info",
            "title": "t", "detail": "d", "subject_field": "m",
            "match": {"field": "m", "operator": "regex", "value": pattern},
        })
        assert rule.operator == "regex"


def test_regex_input_is_truncated_so_a_huge_log_line_stays_cheap():
    rule = EventRule.from_dict({
        "id": "T", "version": 1, "kind": "k", "severity": "info",
        "title": "t", "detail": "d", "subject_field": "m",
        "match": {"field": "m", "operator": "regex", "value": "PHẦN_CUỐI"},
    })
    event = _Event(ts=1.0, source="s", kind="k", data={"m": "x" * 50_000 + "PHẦN_CUỐI"})
    assert rule.matches(event) is False  # phần đuôi nằm ngoài cửa sổ quét


def test_a_missing_placeholder_does_not_break_the_detector():
    """Rule pack là dữ liệu và có thể sai. Một {ip} thiếu không được làm đứt
    cả đường ống alert."""
    detector = RuleDetector([EventRule.from_dict({
        "id": "T", "version": 1, "kind": "k", "severity": "info",
        "title": "t", "detail": "thiếu {không_có_trường_này}", "subject_field": "x",
        "match": {"field": "x", "operator": "exists", "value": True},
    })])
    alerts = detector.handle_event(_Event(ts=1.0, source="s", kind="k", data={"x": 1}))
    assert len(alerts) == 1


def test_unknown_operators_are_still_refused():
    assert "eval" not in ALLOWED_OPERATORS
    with _pytest.raises(ValueError):
        EventRule.from_dict({
            "id": "T", "version": 1, "kind": "k", "severity": "info",
            "title": "t", "detail": "d", "subject_field": "x",
            "match": {"field": "x", "operator": "eval", "value": "1"},
        })
