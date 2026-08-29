"""Hợp đồng `explanation_only`: model chỉ được viết văn, không được lái tool.

Quyết định kiến trúc đã duyệt sau khi đo model thật: intent_accuracy 61,9% so
với cổng 95%, nên model KHÔNG lái vòng lặp tool. Điều đó phải là BẤT KHẢ THI,
không phải "ta sẽ không hỏi" — một lời hứa không phải một hàng rào.
"""

from __future__ import annotations

import pathlib

import pytest

from shield.ai.model_config import AI_MODES, ModelConfig, ModelConfigError
from shield.report.scenarios import (
    EXPLANATION_ELIGIBLE_FAMILIES,
    SCENARIOS,
    UNKNOWN,
    explanation_allowed,
)
from shield.report.template import (
    CONFIRMED_FACT,
    EPISTEMIC_STATES,
    INSUFFICIENT_EVIDENCE,
    SUPPORTED_HYPOTHESIS,
    UNCONFIRMED,
    AiSlots,
    asserts_confirmation,
    epistemic_state,
    render,
)


def _alert(**kw):
    base = {"rule_id": "SCAN_PORTSCAN", "severity": "warning", "risk_score": 61,
            "evidence_strength": 0.6, "subject": "192.168.1.77", "title": "t",
            "detail": "d", "ts": 1000.0, "playbook": ["snapshot_state"],
            "evidence": {"src_ip": "192.168.1.77", "ports": [22, 80]}}
    base.update(kw)
    return base


# --------------------------------------------------------------------------
# B. Chế độ chỉ-giải-thích


def test_every_supported_mode_is_prose_only():
    """Bộ chế độ ĐÓNG, và mọi chế độ trong đó chỉ sinh văn xuôi.

    `chat` thêm vào ở Incident Chat v0. Nó KHÔNG nới vai trò của model: vẫn là
    văn xuôi, vẫn không phân loại, vẫn không công cụ — điều được chứng minh
    ngay dưới đây bằng chính ngữ pháp của nó, chứ không bằng lời hứa.
    """
    from shield.ai.worker.runtime import chat_grammar, explanation_grammar

    assert AI_MODES == {"explanation_only", "chat"}
    assert ModelConfig().mode == "explanation_only", "mặc định phải là chế độ hẹp nhất"
    for grammar in (explanation_grammar(), chat_grammar()):
        lowered = grammar.lower()
        for forbidden in ("tool", "action", "severity", "scenario", "evidence_ref"):
            assert forbidden not in lowered, forbidden


@pytest.mark.parametrize("mode", ["tool_planning", "classification", "full", ""])
def test_any_other_mode_is_refused_at_config_time(mode):
    with pytest.raises(ModelConfigError):
        ModelConfig.parse({"mode": mode})


def test_the_explanation_grammar_cannot_express_a_tool_request():
    """Hàng rào thứ nhất, ở tầng LẤY MẪU: ngữ pháp chỉ có ba khoá, nên model
    không sinh ra `tool_requests` được — không phải "sinh rồi bị loại"."""
    from shield.ai.worker.runtime import explanation_grammar

    import re

    gbnf = explanation_grammar()
    assert "tool_request" not in gbnf
    # Đọc ĐÚNG luật `root` — luật `str` cũng chứa dấu nháy escape, nên đếm
    # trên cả ngữ pháp sẽ đo nhầm thứ.
    root = next(line for line in gbnf.splitlines() if line.startswith("root ::="))
    keys = re.findall(r'\\"([a-z_]+)\\"', root)
    assert keys == ["analysis", "hypothesis_rationale", "why_this_matters"], keys


def test_the_explanation_prompt_never_offers_a_tool():
    from shield.ai.worker.prompt import build_explanation_prompt

    prompt = build_explanation_prompt({"scenario_code": "PORT_SCAN"})
    assert "tool" not in prompt.lower().replace("automated tool", "")
    assert "Never propose or name a response action" in prompt


# --------------------------------------------------------------------------
# C. Allowlist họ — cấu hình CHÍNH DANH, không phải suy đoán ở giao diện


def test_only_the_three_approved_families_may_carry_prose():
    assert EXPLANATION_ELIGIBLE_FAMILIES == {
        "AUTHENTICATION_ATTACK", "RECONNAISSANCE", "MALWARE_EXECUTION"}


@pytest.mark.parametrize("code,allowed", [
    ("SSH_BRUTE_FORCE", True), ("PORT_SCAN", True),
    ("SUSPICIOUS_EXECUTION_CHAIN", True),
    ("AGENT_STOPPED", False), ("INSTALLATION_CHANGED", False),
    ("NEW_DEVICE_ON_NETWORK", False), ("FILE_INTEGRITY_CHANGE", False),
    (UNKNOWN, False), ("", False), ("KHONG_TON_TAI", False),
])
def test_explanation_eligibility_is_deterministic(code, allowed):
    assert explanation_allowed(code) is allowed


def test_an_ineligible_family_renders_with_no_prose_at_all():
    """Cổng nằm ở registry: model nói gì cũng được, ô vẫn rỗng."""
    report = render(_alert(rule_id="GUARDIAN_AGENT_STOPPED"),
                    scenario_code="AGENT_STOPPED", evidence_refs=["e1", "e2"],
                    slots=AiSlots(analysis="Một câu hoàn toàn vô hại.",
                                  why_this_matters="Cũng vô hại."))
    assert report["explanation_eligible"] is False
    assert report["analysis"]["prose"] == ""
    assert report["why_this_matters"]["prose"] == ""
    # ...và báo cáo vẫn đầy đủ.
    assert report["severity"]["level"] == "warning"


def test_unknown_is_always_deterministic_only():
    """Khi Shield còn chưa biết đây là chuyện gì, để model viết vài câu về nó
    là mời nó đoán — ở đúng chỗ ta vừa thú nhận là không biết."""
    report = render(_alert(rule_id="KHONG_CO_ANH_XA"), scenario_code=UNKNOWN,
                    evidence_refs=["e1"], slots=AiSlots(analysis="Đoán bừa."))
    assert report["explanation_eligible"] is False
    assert report["analysis"]["prose"] == ""


def test_eligibility_lives_in_the_registry_not_in_the_ui():
    for path in pathlib.Path("shield/ui").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "EXPLANATION_ELIGIBLE" not in source, path
        assert "explanation_allowed" not in source, path


# --------------------------------------------------------------------------
# D. Guard khẳng định quá tay


def test_the_epistemic_states_are_the_four_agreed_ones():
    assert set(EPISTEMIC_STATES) == {
        CONFIRMED_FACT, SUPPORTED_HYPOTHESIS, UNCONFIRMED, INSUFFICIENT_EVIDENCE}


@pytest.mark.parametrize("refs,minimum,statuses,expected", [
    ([], 1, (), INSUFFICIENT_EVIDENCE),
    (["e1"], 2, (), INSUFFICIENT_EVIDENCE),
    (["e1", "e2"], 2, (), UNCONFIRMED),
    (["e1", "e2"], 2, ("supported",), SUPPORTED_HYPOTHESIS),
    (["e1", "e2"], 2, ("insufficient_evidence",), INSUFFICIENT_EVIDENCE),
])
def test_the_state_is_derived_deterministically(refs, minimum, statuses, expected):
    assert epistemic_state(evidence_refs=refs, minimum_refs=minimum,
                           hypothesis_statuses=statuses) == expected


def test_prose_claiming_confirmation_is_dropped_when_nothing_is_confirmed():
    """Fixture bắt buộc của §D."""
    report = render(_alert(), scenario_code="PORT_SCAN", evidence_refs=["e1", "e2"],
                    state=UNCONFIRMED,
                    slots=AiSlots(analysis="Shield đã xác nhận đây là tấn công.",
                                  why_this_matters="Máy đã bị xâm nhập."))
    assert report["epistemic_state"] == UNCONFIRMED
    assert report["analysis"]["prose"] == ""


def test_correctly_hedged_prose_is_preserved():
    """Bài đối chứng: nếu bài trên xanh chỉ vì guard bỏ MỌI thứ thì nó vô nghĩa."""
    report = render(_alert(), scenario_code="PORT_SCAN", evidence_refs=["e1", "e2"],
                    state=UNCONFIRMED,
                    slots=AiSlots(analysis="Hoạt động này có thể là một lượt quét.",
                                  why_this_matters="Đây có lẽ là bước dò tìm."))
    assert report["analysis"]["prose"] == "Hoạt động này có thể là một lượt quét."
    assert report["why_this_matters"]["prose"] == "Đây có lẽ là bước dò tìm."


def test_a_negated_confirmation_is_not_treated_as_an_assertion():
    """"not a confirmed fact" là rào đón ĐÚNG. Phạt nó là phạt hành vi ta muốn."""
    assert asserts_confirmation("this is not a confirmed fact") is False
    assert asserts_confirmation("điều này chưa được xác nhận") is False
    assert asserts_confirmation("Shield confirmed the breach") is True


def test_confirmed_fact_state_allows_plain_statement():
    report = render(_alert(), scenario_code="PORT_SCAN", evidence_refs=["e1", "e2"],
                    state=CONFIRMED_FACT,
                    slots=AiSlots(analysis="Shield confirmed 2 evidence records."))
    assert report["analysis"]["prose"].startswith("Shield confirmed")


def test_the_guard_is_deterministic_not_a_model():
    import inspect

    import shield.report.template as T

    source = inspect.getsource(T)
    for smell in ("llama", "investigate", "create_completion", "provider"):
        assert smell not in source, smell
