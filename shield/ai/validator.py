"""Validator bằng chứng — tất định, tách khỏi model (mục 2.4).

Đây là thứ đứng giữa "model nói vậy" và "Shield hiển thị vậy". Nó không tin
model một chút nào, kể cả khi model là mã tất định của chính Shield.

Nó không bao giờ XOÁ một giả thuyết. Nó HẠ CẤP và ghi lý do. Xoá nghĩa là người
đọc không biết model đã nói gì và vì sao điều đó bị bác — mà chính khoảng cách
giữa hai thứ đó mới là thông tin: một model liên tục bịa evidence là một model
cần bị tắt, và không ai thấy được điều đó nếu bằng chứng của việc bịa bị dọn đi.

Bốn phép kiểm, theo đúng mục 2.4:

1. Evidence có TỒN TẠI không.
2. Evidence có nằm trong PHẠM VI của investigation không (cửa sổ thời gian và
   tập ref được cấp).
3. Trust có đủ SÀN cho loại khẳng định đó không.
4. Có evidence MÂU THUẪN không.
"""

from __future__ import annotations

import dataclasses

from shield.ai.contracts import Hypothesis, InvestigationRequest, InvestigationResult
from shield.evidence.models import EvidenceKind
from shield.common.models import trust_rank

# Sàn tin cậy để một giả thuyết được mang trạng thái `supported`.
# `unauthenticated` (syslog thô — ai trong LAN cũng giả mạo được) KHÔNG đủ.
SUPPORT_TRUST_FLOOR = "authenticated"

# Số bằng chứng độc lập tối thiểu cho `supported`. Một event đơn lẻ có thể là
# trùng hợp; hai event độc lập thì khó hơn nhiều.
SUPPORT_MIN_EVIDENCE = 2


@dataclasses.dataclass
class ValidationReport:
    """Validator đã làm gì. Hiện được lên UI, không chỉ nằm trong log."""

    checked: int = 0
    downgraded: int = 0
    unknown_refs: list[str] = dataclasses.field(default_factory=list)
    out_of_scope_refs: list[str] = dataclasses.field(default_factory=list)
    reasons: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "checked": self.checked, "downgraded": self.downgraded,
            "unknown_refs": list(self.unknown_refs),
            "out_of_scope_refs": list(self.out_of_scope_refs),
            "reasons": list(self.reasons),
            # Tỉ lệ khẳng định không có căn cứ. Mục 3.2 gọi nó là
            # unsupported-claim rate và bắt đo — đây là chỗ đo.
            "unsupported_claim_rate": round(self.downgraded / self.checked, 3) if self.checked else 0.0,
        }


class EvidenceValidator:
    def __init__(self, queries, *, trust_floor: str = SUPPORT_TRUST_FLOOR,
                 min_evidence: int = SUPPORT_MIN_EVIDENCE) -> None:
        self.queries = queries
        self.trust_floor = trust_floor
        self.min_evidence = min_evidence

    def validate(self, result: InvestigationResult,
                 request: InvestigationRequest) -> tuple[InvestigationResult, ValidationReport]:
        report = ValidationReport()
        checked: list[Hypothesis] = []
        for hypothesis in result.hypotheses:
            report.checked += 1
            fixed, reason = self._check(hypothesis, request, report)
            if reason:
                report.downgraded += 1
                report.reasons.append(f"{hypothesis.id}: {reason}")
            checked.append(fixed)
        return dataclasses.replace(result, hypotheses=tuple(checked)), report

    def _check(self, hypothesis: Hypothesis, request: InvestigationRequest,
               report: ValidationReport) -> tuple[Hypothesis, str]:
        good, reasons = [], []
        for ref in hypothesis.evidence_refs:
            if request.allowed_evidence_refs and ref not in request.allowed_evidence_refs:
                # Ngoài phạm vi: model đang trỏ tới thứ nó không được xem trong
                # lần điều tra này. Có thể là bịa, có thể là rò rỉ ngữ cảnh từ
                # một incident khác — cả hai đều không được tính là bằng chứng.
                report.out_of_scope_refs.append(ref)
                reasons.append("evidence ngoài phạm vi điều tra")
                continue
            record = self.queries.get_evidence(ref)
            if record is None:
                report.unknown_refs.append(ref)
                reasons.append("evidence không tồn tại")
                continue
            good.append((ref, record))

        if not good:
            return self._downgrade(hypothesis, "insufficient_evidence",
                                   "; ".join(dict.fromkeys(reasons)) or "không có bằng chứng nào"), \
                   "; ".join(dict.fromkeys(reasons)) or "không có bằng chứng nào"

        kept = tuple(ref for ref, _ in good)
        hypothesis = dataclasses.replace(hypothesis, evidence_refs=kept)

        if hypothesis.status != "supported":
            # Chỉ `supported` mới cần vượt sàn. Các trạng thái khác đã tự nói
            # rằng chúng chưa kết luận gì.
            return hypothesis, "; ".join(dict.fromkeys(reasons))

        # Mục 5.3: "External intel chỉ corroborate; không một mình xác nhận
        # compromise." Một khẳng định mà MỌI bằng chứng đều là nguồn ngoài thì
        # không được mang trạng thái `supported`, dù nguồn đó đã ký và dù có
        # bao nhiêu nguồn cùng nói. Nguồn ngoài mô tả thế giới nói chung; nó
        # không quan sát được máy này.
        kinds = {str(record.get("evidence_kind", "")) for _, record in good}
        if kinds and kinds <= {EvidenceKind.EXTERNAL_INTEL}:
            return self._downgrade(
                hypothesis, "unconfirmed",
                "chỉ có nguồn ngoài — nguồn ngoài đối chứng được, không xác nhận được"), \
                "chỉ có nguồn ngoài"

        best_trust = max((trust_rank(record.get("trust", "")) for _, record in good), default=0)
        if best_trust < trust_rank(self.trust_floor):
            return self._downgrade(
                hypothesis, "unconfirmed",
                "nguồn không xác thực không thể một mình xác nhận"), \
                "nguồn không xác thực không thể một mình xác nhận"

        if len(good) < self.min_evidence:
            return self._downgrade(
                hypothesis, "unconfirmed",
                f"chỉ có {len(good)} bằng chứng, cần {self.min_evidence}"), \
                f"chỉ có {len(good)} bằng chứng, cần {self.min_evidence}"

        if hypothesis.contradicting_evidence_refs:
            return self._downgrade(
                hypothesis, "contradicted",
                "có bằng chứng mâu thuẫn"), "có bằng chứng mâu thuẫn"

        return hypothesis, "; ".join(dict.fromkeys(reasons))

    @staticmethod
    def _downgrade(hypothesis: Hypothesis, status: str, reason: str) -> Hypothesis:
        return dataclasses.replace(
            hypothesis, status=status, downgrade_reason=reason,
            # Nhãn tin cậy phải đi xuống cùng trạng thái. Một giả thuyết bị hạ
            # xuống `unconfirmed` mà vẫn mang nhãn `high` là mâu thuẫn hiển thị
            # ngay trên màn hình, và người đọc sẽ tin cái nào to hơn.
            confidence_label="low",
        )
