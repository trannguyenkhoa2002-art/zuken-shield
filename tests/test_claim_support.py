"""Chấm KHẲNG ĐỊNH trong văn xuôi của model — tất định, không dùng model thứ hai.

Chấm một model không đáng tin bằng một model không đáng tin khác chỉ chuyển chỗ
của vấn đề, và làm kết quả không lặp lại được. Bộ chấm ở đây là heuristic và
nói thẳng như vậy; nó bắt đúng thứ `OutputValidator` bắt (giá trị bịa) cộng một
lớp về GIỌNG khẳng định.
"""

from __future__ import annotations

import pytest

from shield.ai.contracts import InvestigationRequest
from shield.evals.claim_support import (
    CONTRADICTED,
    NON_FACTUAL,
    SUPPORTED,
    UNSUPPORTED,
    score_claim,
    score_prose,
    split_claims,
)

FACTS = {"src_ip": "192.168.1.77", "fail_count": 37, "user": "backup"}


def _request(facts=None):
    return InvestigationRequest(
        investigation_id="i", incident_id="c",
        facts=(dict(facts or FACTS),),
        allowed_evidence_refs=frozenset({"event:aaa"}))


@pytest.mark.parametrize("sentence,expected", [
    ("There were 37 failed logins from 192.168.1.77.", SUPPORTED),
    ("Đã có 37 lần đăng nhập sai từ 192.168.1.77.", SUPPORTED),
    ("There were 15 failed logins from 192.168.1.77.", CONTRADICTED),
    ("This pattern may indicate credential abuse.", NON_FACTUAL),
    ("Mẫu này có thể là dấu hiệu lạm dụng thông tin đăng nhập.", NON_FACTUAL),
    ("The account was compromised.", UNSUPPORTED),
    ("Tài khoản đã bị xâm nhập.", UNSUPPORTED),
    ("Traffic also came from 8.8.8.8 during the window.", UNSUPPORTED),
])
def test_each_claim_gets_the_right_label(sentence, expected):
    assert score_claim(sentence, _request(), FACTS).label == expected


def test_a_wrong_count_is_contradicted_not_merely_unsupported():
    """Nói 15 khi dữ kiện nói 37 tệ hơn hẳn nói một số không đâu: nó trông có
    căn cứ, và người đọc không có cách nào biết nó sai."""
    claim = score_claim("We observed 15 failures.", _request(), FACTS)
    assert claim.label == CONTRADICTED
    assert "37" in claim.reason


def test_hedged_speculation_is_allowed_not_penalised():
    """Model ĐƯỢC phép suy đoán miễn là nói rõ đang suy đoán. Gộp nó vào
    'không có căn cứ' sẽ phạt đúng hành vi ta muốn khuyến khích."""
    report = score_prose(
        {"analysis": "The host may have been scanned by an automated tool.",
         "hypothesis_rationale": "", "why_this_matters": ""}, _request(), FACTS)
    data = report.to_dict()
    assert data["non_factual"] == 1 and data["unsupported"] == 0
    assert data["explanation_supported_rate"] == 1.0


def test_short_fragments_are_not_counted_as_claims():
    assert split_claims("OK. Yes. No.") == []


def test_an_empty_slot_produces_no_claims():
    report = score_prose({"analysis": "", "hypothesis_rationale": "",
                          "why_this_matters": ""}, _request(), FACTS)
    assert report.total == 0
    # Không có khẳng định nào thì không có khẳng định nào SAI.
    assert report.to_dict()["unsupported_claim_rate"] == 0.0


def test_the_scorer_uses_the_same_canonical_definition_as_the_validator():
    """Một định nghĩa 'giá trị chuẩn tắc' thứ hai sẽ lệch khỏi cái thứ nhất."""
    import inspect

    import shield.evals.claim_support as C

    source = inspect.getsource(C)
    assert "canonical_tokens" in source and "_khong_chuan_tac" in source


def test_the_scorer_never_calls_a_model():
    import inspect

    import shield.evals.claim_support as C

    source = inspect.getsource(C)
    for smell in ("llama", "Llama", "investigate", "create_completion", "provider"):
        assert smell not in source, smell
