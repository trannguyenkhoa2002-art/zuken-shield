"""Chấm câu trả lời hỏi đáp theo ý định. TẤT ĐỊNH, dùng cho eval — không phải sản phẩm.

Cùng nguyên tắc như bộ chấm claim của phase giải thích: không có model thứ hai
chấm model thứ nhất. Mọi tiêu chí ở đây đều đo được bằng luật trên văn bản và
dữ liệu chuẩn tắc.
"""

from __future__ import annotations

import re
import unicodedata

# Lặp: cùng một mệnh đề xuất hiện lại. Đo bằng tỉ lệ n-gram trùng, không bằng
# cảm nhận — bản mở đã sinh ra "Nó đã xác định rằng Shield đã phân tích..." ba
# lần trong một câu trả lời.
_NGRAM = 5
_REPEAT_RATIO = 0.30


def _fold(text: str) -> list[str]:
    lowered = unicodedata.normalize("NFD", str(text or "").lower())
    lowered = "".join(c for c in lowered if not unicodedata.combining(c))
    return re.findall(r"[a-z0-9_:.]+", lowered.replace("đ", "d"))


def repetition_ratio(text: str) -> float:
    """Tỉ lệ n-gram bị lặp. 0 = không lặp."""
    words = _fold(text)
    if len(words) < _NGRAM * 2:
        return 0.0
    grams = [tuple(words[i:i + _NGRAM]) for i in range(len(words) - _NGRAM + 1)]
    return 1.0 - (len(set(grams)) / len(grams))


def is_repetitive(text: str) -> bool:
    return repetition_ratio(text) >= _REPEAT_RATIO


def grounded(text: str, allowed: frozenset) -> bool:
    """Câu trả lời có nhắc ít nhất một giá trị chuẩn tắc không.

    Không bắt buộc với mọi ý định — một câu về mức chắc chắn có thể không nêu
    số nào. Chỗ gọi quyết định khi nào tiêu chí này áp dụng.
    """
    return any(token and token in text for token in allowed)


def unsupported_values(text: str, allowed: frozenset) -> list[str]:
    """Số/định danh xuất hiện trong câu trả lời mà KHÔNG có trong dữ liệu.

    Đây là bản đo của eval. Sản phẩm đã chặn bằng `clean_prose`; nếu bộ này
    tìm thấy gì thì nghĩa là bộ chặn kia đã thủng.
    """
    found = []
    for token in re.findall(r"\b\d{2,}\b|\b\d+\.\d+\.\d+\.\d+\b", str(text or "")):
        if token not in allowed and not any(token in value for value in allowed):
            found.append(token)
    return found


def contradicts_state(text: str, state: str) -> bool:
    """Khẳng định chắc chắn trong khi Shield chưa xác nhận."""
    from shield.report.template import asserts_confirmation

    return state != "CONFIRMED_FACT" and asserts_confirmation(text)


def useful(text: str, *, allowed: frozenset, state: str,
           require_grounding: bool) -> bool:
    """Có dùng được không: đủ dài, không lặp, không mâu thuẫn, có căn cứ."""
    if len(str(text or "").strip()) < 40:
        return False
    if is_repetitive(text):
        return False
    if contradicts_state(text, state):
        return False
    if require_grounding and not grounded(text, allowed):
        return False
    return True
