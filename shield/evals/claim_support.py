"""Chấm từng KHẲNG ĐỊNH trong văn xuôi của model (Phase 3D, mục 5).

Không chấm bằng so chuỗi chính xác — hai câu đúng như nhau có thể viết khác
nhau, và một bộ đo phạt cách diễn đạt sẽ đo phong cách chứ không đo sự thật.
Cũng KHÔNG dùng một model thứ hai để chấm: chấm một model không đáng tin bằng
một model không đáng tin khác chỉ chuyển chỗ của vấn đề, và làm kết quả không
lặp lại được.

Cách làm: tách câu, rồi hỏi hai câu hỏi TẤT ĐỊNH về mỗi câu.

1. **Câu này có nêu con số hay định danh nào không?** Nếu có, chúng phải khớp
   dữ liệu chuẩn tắc. Dùng lại đúng bộ nhận dạng của `shield/ai/report.py` —
   một định nghĩa "giá trị chuẩn tắc" thứ hai sẽ lệch khỏi cái thứ nhất.
2. **Câu này có khẳng định một kết luận không?** "Máy đã bị xâm nhập" là một
   kết luận; "mẫu này có thể là dấu hiệu của..." thì không. Shield xác nhận,
   model giải thích.

Bốn nhãn, và ranh giới giữa chúng là điểm của cả file:

- `SUPPORTED` — mọi giá trị nêu ra đều khớp dữ liệu chuẩn tắc.
- `CONTRADICTED` — nêu một giá trị MÂU THUẪN với dữ kiện chuẩn tắc cùng loại
  (nói 15 khi dữ liệu nói 37). Đây là dạng tệ nhất: nó trông có căn cứ.
- `UNSUPPORTED` — khẳng định một kết luận mà không có gì xác nhận, hoặc nêu
  một giá trị không có trong dữ liệu.
- `NON_FACTUAL_EXPLANATION` — diễn giải có rào đón, không nêu giá trị nào.
  Đây là thứ model ĐƯỢC phép viết, và nó không phải lỗi.

Bộ chấm này là HEURISTIC, và nói thẳng như vậy. Nó bắt được đúng những gì
`OutputValidator` bắt (giá trị bịa) cộng một lớp về giọng khẳng định. Nó không
hiểu ngữ nghĩa, và không giả vờ hiểu.
"""

from __future__ import annotations

import dataclasses
import re

from shield.ai.report import _khong_chuan_tac, canonical_tokens  # noqa: PLC2701

SUPPORTED = "SUPPORTED"
UNSUPPORTED = "UNSUPPORTED"
CONTRADICTED = "CONTRADICTED"
NON_FACTUAL = "NON_FACTUAL_EXPLANATION"

# Câu có rào đón. Model được phép suy đoán MIỄN LÀ nó nói rõ đang suy đoán.
_HEDGES = (
    "may ", "might ", "could ", "possibly", "possible", "likely", "suggests",
    "suggest ", "appears", "seems", "consistent with", "typically", "often",
    "can be", "would be", "unclear", "not known", "cannot be confirmed",
    "có thể", "có lẽ", "dường như", "gợi ý", "thường", "chưa rõ", "chưa biết",
    "không xác nhận được", "phù hợp với", "nghi ngờ",
)

# Giọng KHẲNG ĐỊNH một kết luận. Model không được kết luận — đó là việc của
# con người sau khi đọc bằng chứng, hoặc của một quy tắc tất định.
_ASSERTIONS = (
    "was compromised", "is compromised", "has been compromised", "confirmed",
    "we confirm", "definitely", "certainly", "proves", "proven", "is malicious",
    "was malicious", "an attacker ", "the attacker ", "successfully breached",
    "đã bị xâm nhập", "bị xâm nhập", "chắc chắn", "xác nhận", "chứng minh",
    "kẻ tấn công đã", "là mã độc", "đã chiếm được",
)

# Phủ định đi kèm một từ khẳng định. "not a confirmed fact" là câu RÀO ĐÓN
# ĐÚNG, không phải một khẳng định — bản đầu của bộ chấm gắn nhãn UNSUPPORTED
# cho đúng câu model làm ĐÚNG, tức là phạt hành vi ta muốn khuyến khích.
_NEGATED = (
    "not confirmed", "not a confirmed", "cannot be confirmed", "unconfirmed",
    "not yet confirmed", "no confirmation", "is an inference",
    "chưa xác nhận", "không xác nhận", "chưa được xác nhận",
)

# Giờ viết dạng `HH:MM`. `local_hour=13` hiện ra thành "13:00" là cách VIẾT ĐÚNG
# của một dữ kiện chuẩn tắc, nhưng bản đầu đọc "00" như một con số bịa. Bỏ phần
# phút khỏi câu trước khi soi, khi giờ khớp dữ kiện.
_CLOCK = re.compile(r"\b(\d{1,2}):([0-5]\d)\b")

_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclasses.dataclass(frozen=True)
class Claim:
    text: str
    label: str
    reason: str = ""


def split_claims(prose: str) -> list[str]:
    """Văn xuôi -> câu. Bỏ câu quá ngắn để không đếm mảnh vụn thành khẳng định."""
    parts = [p.strip() for p in _SENTENCE.split(prose or "") if p and p.strip()]
    return [p for p in parts if len(p) >= 12]


def _numeric_facts(facts: dict) -> dict[str, set[str]]:
    """Giá trị chuẩn tắc theo tên trường, để phát hiện MÂU THUẪN chứ không chỉ
    phát hiện 'lạ'. Nói 15 khi dữ liệu nói 37 tệ hơn hẳn nói một số không đâu."""
    out: dict[str, set[str]] = {}
    for key, value in (facts or {}).items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out.setdefault(key, set()).add(str(value))
        elif isinstance(value, str) and value:
            out.setdefault(key, set()).add(value)
        elif isinstance(value, (list, tuple)):
            out.setdefault(key, set()).update(str(v) for v in value)
    return out


def _strip_clock(sentence: str, allowed) -> str:
    """Bỏ `:MM` khi giờ đã là một giá trị chuẩn tắc.

    Giữ nguyên khi giờ KHÔNG khớp dữ liệu — lúc đó "07:00" thật sự là một giá
    trị model tự nghĩ ra, và nó phải bị bắt.
    """
    def replace(match):
        hour = match.group(1)
        return hour if hour in allowed or hour.lstrip("0") in allowed else match.group(0)

    return _CLOCK.sub(replace, sentence)


def score_claim(sentence: str, request, facts: dict) -> Claim:
    """Một câu -> một nhãn. Tất định."""
    allowed = canonical_tokens(request)
    stray = _khong_chuan_tac(_strip_clock(sentence, allowed), allowed)
    lowered = sentence.lower()
    hedged = any(mark in lowered for mark in _HEDGES)
    negated = any(mark in lowered for mark in _NEGATED)
    asserted = any(mark in lowered for mark in _ASSERTIONS) and not negated

    if stray:
        # Có nêu giá trị không có trong dữ liệu chuẩn tắc. Nếu cùng loại với
        # một dữ kiện đã biết thì đó là MÂU THUẪN, không chỉ là bịa.
        numeric = _numeric_facts(facts)
        for values in numeric.values():
            if any(v.isdigit() and len(v) >= 2 for v in values) and \
                    any(s.isdigit() for s in stray):
                return Claim(sentence, CONTRADICTED,
                             f"nêu {stray[:3]} trong khi dữ kiện nói {sorted(values)[:3]}")
        return Claim(sentence, UNSUPPORTED, f"giá trị không có trong dữ liệu: {stray[:3]}")

    if asserted and not hedged:
        return Claim(sentence, UNSUPPORTED, "khẳng định một kết luận mà không có xác nhận")
    if hedged:
        return Claim(sentence, NON_FACTUAL, "diễn giải có rào đón")
    return Claim(sentence, SUPPORTED, "mọi giá trị nêu ra đều khớp dữ liệu chuẩn tắc")


@dataclasses.dataclass
class ClaimReport:
    supported: int = 0
    unsupported: int = 0
    contradicted: int = 0
    non_factual: int = 0
    claims: list = dataclasses.field(default_factory=list)

    @property
    def total(self) -> int:
        return self.supported + self.unsupported + self.contradicted + self.non_factual

    def to_dict(self) -> dict:
        total = self.total or 1
        return {
            "claims": self.total,
            "supported": self.supported, "unsupported": self.unsupported,
            "contradicted": self.contradicted, "non_factual": self.non_factual,
            # `NON_FACTUAL` tính là ĐƯỢC PHÉP: model có quyền diễn giải miễn là
            # nó rào đón. Gộp nó vào "không có căn cứ" sẽ phạt đúng hành vi ta
            # muốn khuyến khích.
            "explanation_supported_rate": (self.supported + self.non_factual) / total,
            "unsupported_claim_rate": self.unsupported / total,
            "contradiction_rate": self.contradicted / total,
        }


def score_prose(slots: dict, request, facts: dict) -> ClaimReport:
    """Ba ô -> báo cáo khẳng định."""
    report = ClaimReport()
    for name in ("analysis", "hypothesis_rationale", "why_this_matters"):
        for sentence in split_claims(str(slots.get(name, "") or "")):
            claim = score_claim(sentence, request, facts)
            report.claims.append({"slot": name, "label": claim.label,
                                  "reason": claim.reason, "text": claim.text[:160]})
            if claim.label == SUPPORTED:
                report.supported += 1
            elif claim.label == UNSUPPORTED:
                report.unsupported += 1
            elif claim.label == CONTRADICTED:
                report.contradicted += 1
            else:
                report.non_factual += 1
    return report
