"""Bộ chấm khẳng định tự chấm chính nó (Phase 3D §E).

Một bộ đo không có sai số đã biết là một bộ đo không ai kiểm được. Bộ này dán
nhãn BẰNG TAY 30 câu — gồm cả hai lớp dương-tính-giả đã chứng minh được trên
model thật — rồi báo precision/recall cho từng nhãn.

Nó là CÔNG CỤ ĐÁNH GIÁ, không phải validator sản phẩm. `OutputValidator` và
`asserts_confirmation()` mới là thứ chặn ở đường ra; file này chỉ nói cho ta
biết con số eval đáng tin tới đâu.
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
)

FACTS = {"src_ip": "192.168.1.77", "fail_count": 37, "user": "backup",
         "local_hour": 13, "mac": "02:00:5e:10:00:01", "ports": [22, 80, 443]}

# (câu, nhãn ĐÚNG do người dán). Cân bằng bốn nhãn có chủ ý.
LABELLED = [
    # --- SUPPORTED: nêu giá trị, mọi giá trị đều khớp ---
    ("There were 37 failed logins from 192.168.1.77.", SUPPORTED),
    ("Đã ghi nhận 37 lần đăng nhập sai từ 192.168.1.77.", SUPPORTED),
    ("The device was seen at 13:00 with MAC 02:00:5e:10:00:01.", SUPPORTED),
    ("Ports 22, 80 and 443 were probed.", SUPPORTED),
    ("Tài khoản backup là đối tượng của các lần thử.", SUPPORTED),
    ("The source address 192.168.1.77 appears in every record.", SUPPORTED),
    ("Thiết bị xuất hiện vào lúc 13:00.", SUPPORTED),
    # Lớp dương-tính-giả #1 đã chứng minh: phủ định chứa từ "confirmed".
    ("However, this is an inference and not a confirmed fact.", SUPPORTED),
    ("Điều này chưa được xác nhận bằng bằng chứng nào.", SUPPORTED),

    # --- NON_FACTUAL: diễn giải có rào đón, không nêu giá trị lạ ---
    ("This pattern may indicate automated credential guessing.", NON_FACTUAL),
    ("Mẫu này có thể là dấu hiệu của việc dò mật khẩu tự động.", NON_FACTUAL),
    ("The activity is consistent with a scanning tool.", NON_FACTUAL),
    ("It seems the source is probing common service ports.", NON_FACTUAL),
    ("Có lẽ đây là một công cụ quét tự động.", NON_FACTUAL),
    ("The cause is unclear from the available data.", NON_FACTUAL),
    ("Chưa rõ vì sao hành vi này xuất hiện.", NON_FACTUAL),
    ("This could be a misconfigured backup client.", NON_FACTUAL),

    # --- UNSUPPORTED: khẳng định kết luận, hoặc nêu giá trị không có ---
    ("The account was compromised.", UNSUPPORTED),
    ("Tài khoản đã bị xâm nhập.", UNSUPPORTED),
    ("Shield đã xác nhận đây là một cuộc tấn công.", UNSUPPORTED),
    ("We confirm the host is malicious.", UNSUPPORTED),
    ("Traffic also originated from 8.8.8.8 during the window.", UNSUPPORTED),
    ("An attacker gained access to the machine.", UNSUPPORTED),
    ("Kẻ tấn công đã chiếm được quyền quản trị.", UNSUPPORTED),

    # --- CONTRADICTED: nêu giá trị MÂU THUẪN với dữ kiện cùng loại ---
    ("There were 15 failed logins from 192.168.1.77.", CONTRADICTED),
    ("Chỉ có 12 lần đăng nhập sai được ghi nhận.", CONTRADICTED),
    ("The device was first seen at 07:00.", CONTRADICTED),
    ("A total of 99 attempts were recorded.", CONTRADICTED),
    ("Có 21 cổng bị dò trong cửa sổ quan sát.", CONTRADICTED),
    ("The count reached 250 within the hour.", CONTRADICTED),
]


def _request():
    return InvestigationRequest(investigation_id="i", incident_id="c",
                                facts=(dict(FACTS),))


def _confusion():
    request = _request()
    matrix: dict = {}
    for sentence, truth in LABELLED:
        got = score_claim(sentence, request, FACTS).label
        matrix[(truth, got)] = matrix.get((truth, got), 0) + 1
    return matrix


def _precision_recall(matrix, label):
    tp = matrix.get((label, label), 0)
    fp = sum(n for (truth, got), n in matrix.items() if got == label and truth != label)
    fn = sum(n for (truth, got), n in matrix.items() if truth == label and got != label)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return precision, recall


def test_the_labelled_set_is_balanced_enough_to_mean_something():
    from collections import Counter

    counts = Counter(label for _, label in LABELLED)
    assert len(LABELLED) >= 30
    for label in (SUPPORTED, NON_FACTUAL, UNSUPPORTED, CONTRADICTED):
        assert counts[label] >= 6, f"{label} chỉ có {counts[label]} mẫu"


@pytest.mark.parametrize("label", [SUPPORTED, NON_FACTUAL, UNSUPPORTED, CONTRADICTED])
def test_each_label_reaches_a_usable_precision_and_recall(label):
    """Ngưỡng 0,80 chọn có chủ ý và KHÔNG cao: đây là công cụ eval, không phải
    hàng rào sản phẩm. Đặt nó ở 0,95 sẽ khiến ta chỉnh bộ chấm cho vừa con số
    thay vì chỉnh cho đúng."""
    precision, recall = _precision_recall(_confusion(), label)
    assert precision is not None and recall is not None, label
    assert precision >= 0.80, f"{label} precision={precision:.2f}"
    assert recall >= 0.80, f"{label} recall={recall:.2f}"


def test_the_two_demonstrated_false_positive_classes_are_fixed():
    """Cả hai lớp này quan sát được trên model thật ở lượt eval trước."""
    request = _request()
    # 1. Phủ định chứa từ "confirmed" — model đang rào đón ĐÚNG.
    assert score_claim("However, it is important to note that this is an "
                       "inference and not a confirmed fact.",
                       request, FACTS).label != UNSUPPORTED
    # 2. Giờ chuẩn tắc viết dạng HH:MM.
    assert score_claim("The device was seen at 13:00.", request, FACTS).label == SUPPORTED
    # ...nhưng một giờ KHÁC vẫn phải bị bắt.
    assert score_claim("The device was seen at 07:00.", request, FACTS).label == CONTRADICTED


def test_the_scorer_is_labelled_diagnostic_not_a_gate():
    """Bộ chấm heuristic KHÔNG được trở thành validator sản phẩm."""
    import pathlib

    source = pathlib.Path("shield/evals/claim_support.py").read_text(encoding="utf-8")
    assert "CÔNG CỤ" in source or "heuristic" in source.lower()
    # Và không mã sản phẩm nào ngoài `shield/evals` được nhập nó.
    for path in pathlib.Path("shield").rglob("*.py"):
        if path.parts[1] == "evals":
            continue
        assert "claim_support" not in path.read_text(encoding="utf-8"), path
