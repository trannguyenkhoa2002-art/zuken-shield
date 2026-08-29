"""Tầng cuối giữa "model nói vậy" và "người dùng đọc vậy" (Phase 3A).

`EvidenceValidator` đã kiểm được rằng một giả thuyết có bằng chứng tồn tại,
trong phạm vi, đủ tin cậy và không mâu thuẫn. Nó KHÔNG kiểm được thứ nguy hiểm
nhất còn lại: **những con số và định danh nằm trong CÂU VĂN của model**.

Một model có thể vượt qua toàn bộ validator hiện có rồi vẫn viết:

    "15 kết nối từ 10.0.0.9"

trong khi dữ liệu chuẩn tắc nói `count=12`, `src_ip=10.0.0.8`. Câu đó đi thẳng
tới người đọc, và người đọc không có cách nào biết nó sai. Không ref nào bị
bịa, không giả thuyết nào bị hạ cấp, mọi chỉ số đều xanh.

Nguyên tắc của file này: **model không bao giờ là nguồn sự thật cho một sự kiện
có thể đếm hay định danh được.** Nó chỉ được viết phần diễn giải, và phần đó
chỉ được hiển thị khi mọi con số/định danh trong đó đều khớp dữ liệu chuẩn tắc.

Nếu không khớp: bỏ CẢ đoạn văn, đếm lại, và hiển thị phần tất định. Bỏ cả đoạn
chứ không vá từng chỗ, vì một câu bị vá nửa vời vẫn đọc như một câu do người
viết — và đó chính là thứ làm nó thuyết phục.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re

from shield.ai.contracts import InvestigationRequest, InvestigationResult
from shield.ai.redaction import redact_text

# Số có TỪ HAI CHỮ SỐ trở lên phải khớp dữ liệu chuẩn tắc. Một chữ số thì
# không: "3 bước", "2 tiến trình" là cách nói thường ngày và gần như không mang
# trọng lượng của một khẳng định đếm được. Đây là một ngưỡng có chủ đích, và nó
# nghiêng về phía bỏ sót một khẳng định nhỏ hơn là bỏ nhầm mọi câu văn.
_SO_NHIEU_CHU_SO = re.compile(r"\b\d{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
# event_id, content_hash, sha256: chuỗi hex dài. Model không được nêu chúng.
_HEX_DAI = re.compile(r"\b[0-9a-fA-F]{16,}\b")

# Model KHÔNG phải nguồn sự thật cho những thứ này. Danh sách để lộ ra đây,
# không chôn trong hàm, vì nó là một quyết định an ninh chứ không phải chi tiết
# cài đặt.
# Hợp đồng bắt buộc mỗi giả thuyết có `statement` không rỗng — có lý do: một
# giả thuyết không có phát biểu thì không phải một giả thuyết. Nên khi bỏ câu
# văn, ta KHÔNG để rỗng mà thay bằng một khoá dịch: đó chính là cơ chế "agent
# nói bằng mã, giao diện dịch" mà hợp đồng đã dựng sẵn (`statement_key`, thứ
# model không được đặt).
PROSE_DROPPED_KEY = "report.prose_dropped"
_PROSE_PLACEHOLDER = "—"

CRITICAL_FACT_KINDS = (
    "ip", "port", "pid", "process_identity", "event_id", "incident_id",
    "alert_id", "timestamp", "count", "severity", "risk_score",
    "action_level", "hash", "signature_status",
)


@dataclasses.dataclass
class OutputMetrics:
    """Đếm được bằng máy, không phải một câu trong `detail`.

    Đây là lần thứ năm cùng một lớp lỗi trong dự án này — agent sinh ra một CÂU
    thay vì sinh ra DỮ LIỆU — nên các cổng của 3D' bắt đầu ngay ở đây.
    """

    invented_evidence_refs: int = 0
    out_of_scope_refs: int = 0
    incorrect_deterministic_facts: int = 0
    unsupported_claims: int = 0
    contradictory_claims: int = 0
    render_fallbacks: int = 0

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    def model_misbehaved(self) -> bool:
        """Model có bịa gì không. Đây là số liệu về MODEL, không phải về đầu ra.

        Cố ý KHÔNG gọi là `clean()`: ba cổng nghiệm thu của Phase 3A đo ĐẦU RA
        CUỐI, và model được phép bịa trong bản gốc. Trộn hai thứ này lại thì
        một model tồi sẽ làm cổng đỏ dù người dùng chưa bao giờ nhìn thấy điều
        nó bịa — và cổng đó sẽ bị nới ra, rồi mất tác dụng.
        """
        return (self.invented_evidence_refs > 0
                or self.out_of_scope_refs > 0
                or self.incorrect_deterministic_facts > 0)


def canonical_tokens(request: InvestigationRequest) -> frozenset[str]:
    """Mọi giá trị nguyên tử mà model ĐƯỢC PHÉP nhắc tới.

    Dựng từ chính `InvestigationRequest` — thứ Shield đã đưa cho model — nên
    không có đường nào để một giá trị lọt vào đây mà không đi qua telemetry
    chuẩn tắc.
    """
    out: set[str] = {str(request.incident_id), str(request.investigation_id)}
    out.update(str(ref) for ref in request.allowed_evidence_refs)

    def gom(value, sau: int = 0) -> None:
        if sau > 4:
            return
        if isinstance(value, dict):
            for item in value.values():
                gom(item, sau + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                gom(item, sau + 1)
        elif isinstance(value, bool):
            return
        elif isinstance(value, (int, float, str)):
            text = str(value)
            out.add(text)
            # Một IP hay một cổng thường nằm lẫn trong một chuỗi lớn hơn
            # ("10.0.0.8:443", "1234:56789"). Tách ra để so từng phần.
            for phan in re.split(r"[\s,;|]+", text):
                if phan:
                    out.add(phan)
                    out.update(_IPV4.findall(phan))
                    out.update(_SO_NHIEU_CHU_SO.findall(phan))

    for fact in request.facts:
        gom(fact)
    for entity in request.entities:
        gom(entity)
    return frozenset(out)


def _khong_chuan_tac(text: str, cho_phep: frozenset[str]) -> list[str]:
    """Những mẩu trong câu văn KHÔNG có trong dữ liệu chuẩn tắc."""
    la: list[str] = []
    for mau in (_IPV4, _IPV6, _HEX_DAI, _SO_NHIEU_CHU_SO):
        for hit in mau.findall(text or ""):
            if mau is _IPV6:
                # `_IPV6` bắt cả những thứ không phải địa chỉ (ví dụ "12:34").
                # Chỉ tính khi nó thật sự phân tích được thành một địa chỉ.
                try:
                    ipaddress.ip_address(hit)
                except ValueError:
                    continue
            if hit not in cho_phep:
                la.append(hit)
    return la


class OutputValidator:
    """Bọc `EvidenceValidator`, thêm hai thứ nó không kiểm: số liệu trong câu
    văn, và bí mật trên đường ra.

    KHÔNG phải một vũ trụ validation thứ hai: mọi phép kiểm về bằng chứng vẫn
    do `EvidenceValidator` làm, và kết quả của nó được dùng nguyên vẹn.
    """

    def __init__(self, evidence_validator) -> None:
        self.evidence = evidence_validator

    def validate(self, result: InvestigationResult, request: InvestigationRequest):
        """-> (kết quả đã kiểm, báo cáo bằng chứng, chỉ số, câu văn bị bỏ)."""
        validated, report = self.evidence.validate(result, request)

        # `EvidenceValidator` kiểm PHẠM VI trước SỰ TỒN TẠI, nên một ref bịa
        # hoàn toàn rơi vào "ngoài phạm vi" và `invented_evidence_refs` gần như
        # không bao giờ khác 0. Hai thứ này cần phân biệt được: ref ngoài phạm
        # vi có thể là rò rỉ ngữ cảnh từ một incident khác, còn ref bịa là model
        # đang dựng chuyện. Phân loại lại ở đây bằng chính `queries` của
        # validator — không hỏi thêm nguồn nào khác, không đổi validator.
        bia_dat, ngoai_pham_vi = 0, 0
        for ref in report.out_of_scope_refs:
            if self.evidence.queries.get_evidence(ref) is None:
                bia_dat += 1
            else:
                ngoai_pham_vi += 1
        metrics = OutputMetrics(
            invented_evidence_refs=len(report.unknown_refs) + bia_dat,
            out_of_scope_refs=ngoai_pham_vi,
            unsupported_claims=sum(1 for h in validated.hypotheses
                                   if h.status == "insufficient_evidence"),
            contradictory_claims=sum(1 for h in validated.hypotheses
                                     if h.status == "contradicted"),
        )

        cho_phep = canonical_tokens(request)
        bi_bo: dict[str, list[str]] = {}

        # THỨ TỰ QUAN TRỌNG: kiểm giá trị chuẩn tắc trên văn bản GỐC, rồi mới
        # che bí mật. Làm ngược lại thì `redact_text` — vốn thay CẢ chuỗi khi
        # thấy một bí mật — sẽ xoá luôn bằng chứng của việc bịa số, và một model
        # giấu được số liệu bịa chỉ bằng cách chèn thêm một chuỗi trông như
        # khoá API.
        summary = validated.summary or ""
        la = _khong_chuan_tac(summary, cho_phep)
        if la:
            metrics.incorrect_deterministic_facts += len(la)
            metrics.render_fallbacks += 1
            bi_bo["summary"] = la
            summary = ""
        else:
            summary = redact_text(summary)

        hop_le = frozenset(
            ref for ref in request.allowed_evidence_refs
            if self.evidence.queries.get_evidence(ref) is not None)

        hypotheses = []
        for hypothesis in validated.hypotheses:
            # `EvidenceValidator` CỐ Ý giữ lại ref xấu khi hạ cấp một giả
            # thuyết — mất dấu vết model đã viện dẫn gì thì mất luôn bằng chứng
            # của việc nó bịa. Đúng cho audit, nhưng bản render tới người dùng
            # thì không được hiện chúng như bằng chứng thật. Lọc ở ĐÂY, và giữ
            # phần bị loại trong `bi_bo` để audit vẫn thấy.
            xau = [r for r in hypothesis.evidence_refs if r not in hop_le]
            if xau:
                bi_bo[f"evidence_refs:{hypothesis.id}"] = xau
                hypothesis = dataclasses.replace(
                    hypothesis,
                    evidence_refs=tuple(r for r in hypothesis.evidence_refs if r in hop_le))
            statement = hypothesis.statement or ""
            la = _khong_chuan_tac(statement, cho_phep)
            if la:
                metrics.incorrect_deterministic_facts += len(la)
                metrics.render_fallbacks += 1
                bi_bo[f"hypothesis:{hypothesis.id}"] = la
                hypotheses.append(dataclasses.replace(
                    hypothesis, statement=_PROSE_PLACEHOLDER,
                    statement_key=PROSE_DROPPED_KEY))
                continue
            hypotheses.append(dataclasses.replace(
                hypothesis, statement=redact_text(statement)))

        validated = dataclasses.replace(validated, summary=summary,
                                        hypotheses=tuple(hypotheses))
        return validated, report, metrics, bi_bo


# --------------------------------------------------------------------------
# Renderer tất định
#
# Sinh KHOÁ, không sinh câu. Agent không được viết câu cho người đọc — đó là
# bất biến đã phải học ba lần trong dự án này, và một lần nữa ở Guardian.


def render_report(result: InvestigationResult, request: InvestigationRequest,
                  metrics: OutputMetrics) -> dict:
    """Kết quả đã kiểm -> báo cáo có cấu trúc, tất định, lặp lại được từng byte.

    Hai vùng tách bạch, và ranh giới giữa chúng là điểm quan trọng nhất của cả
    Phase 3A:

    - `deterministic`: lấy TỪ dữ liệu chuẩn tắc. Model không chạm vào được.
    - `prose`: câu của model. Chỉ có mặt khi mọi con số/định danh trong đó đều
      khớp dữ liệu chuẩn tắc; nếu không thì rỗng, và `render_fallbacks` đã đếm.
    """
    entities = tuple(sorted(
        (str(e.get("id") or e.get("key") or "") for e in request.entities), key=str))
    return {
        "schema_version": 1,
        "identity": {
            "investigation_id": str(result.investigation_id),
            "incident_id": str(result.incident_id),
            "window_s": float(request.window_s),
            "analysed_ts": float(result.analysed_ts),
            "provider": str(result.provider),
            "model": str(result.model),
        },
        "deterministic": {
            "entities": [e for e in entities if e],
            "evidence_refs": sorted(request.allowed_evidence_refs),
            "fact_count": len(request.facts),
            "entity_count": len(request.entities),
            "hypothesis_count": len(result.hypotheses),
        },
        "hypotheses": [
            {
                "id": h.id,
                "status": h.status,
                "confidence_label": h.confidence_label,
                "evidence_refs": list(h.evidence_refs),
                "contradicting_evidence_refs": list(h.contradicting_evidence_refs),
                "downgrade_reason_key": _reason_key(h.downgrade_reason),
                # Câu của model, đã kiểm. Rỗng nghĩa là đã bị bỏ, và
                # `statement_key` nói vì sao — bằng khoá, không bằng câu.
                "prose": "" if h.statement_key == PROSE_DROPPED_KEY else h.statement,
                "statement_key": h.statement_key,
                "statement_params": dict(h.statement_params),
            }
            for h in result.hypotheses
        ],
        "prose": {"summary": result.summary,
                  "dropped": bool(metrics.render_fallbacks)},
        "limitations": {
            "keys": list(result.limitation_keys),
            "text": [redact_text(item) for item in result.limitations],
        },
        "metrics": metrics.to_dict(),
        # Không dịch: đây là dữ liệu, không phải câu.
        "untranslated_fields": ["identity", "deterministic", "metrics"],
    }


_REASON_KEYS = {
    "insufficient_evidence": "report.downgrade.insufficient_evidence",
    "contradicted": "report.downgrade.contradicted",
    "unconfirmed": "report.downgrade.unconfirmed",
}


def _reason_key(reason: str) -> str:
    """Lý do hạ cấp -> khoá dịch. Câu tiếng Việt từ validator KHÔNG đi ra UI."""
    if not reason:
        return ""
    text = str(reason)
    if "ngoài phạm vi" in text:
        return "report.downgrade.out_of_scope"
    if "không tồn tại" in text:
        return "report.downgrade.unknown_evidence"
    if "mâu thuẫn" in text:
        return "report.downgrade.contradicted"
    if "nguồn ngoài" in text:
        return "report.downgrade.external_only"
    if "không xác thực" in text:
        return "report.downgrade.untrusted_source"
    if "cần" in text:
        return "report.downgrade.insufficient_evidence"
    return "report.downgrade.other"


def final_output_is_clean(report: dict, request: InvestigationRequest) -> dict:
    """Ba cổng nghiệm thu của Phase 3A, đo trên CHÍNH bản đã render.

    Không tin bộ đếm: bộ đếm nói validator nghĩ nó đã làm gì, còn hàm này đọc
    thứ người dùng thật sự nhận được. Nếu hai bên bất đồng thì bên này đúng.
    """
    cho_phep = canonical_tokens(request)
    hop_le = set(request.allowed_evidence_refs)
    van = " ".join([report["prose"]["summary"]]
                   + [h["prose"] for h in report["hypotheses"]])
    refs = [r for h in report["hypotheses"] for r in h["evidence_refs"]]
    return {
        "invented_evidence_refs": sum(1 for r in refs if r not in hop_le),
        "out_of_scope_refs": sum(1 for r in refs if r not in hop_le),
        "incorrect_deterministic_facts": len(_khong_chuan_tac(van, cho_phep)),
    }
