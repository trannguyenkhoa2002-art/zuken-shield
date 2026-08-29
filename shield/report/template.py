"""Khuôn báo cáo CỐ ĐỊNH và quyền sở hữu trường (mục 3–5 của Phase 3D).

Bộ khung 12 mục là như nhau cho MỌI kịch bản, kể cả `UNKNOWN`. Không phải vì
gọn, mà vì một người trực đọc báo cáo thứ hai mươi lúc 3 giờ sáng phải biết
"Recommended next steps" nằm ở đâu mà không cần đọc lại từ đầu. Một model tự
sắp xếp lại bố cục cho mỗi sự cố lấy mất đúng điều đó.

**Quyền sở hữu trường** là bất biến trung tâm. Renderer sở hữu mọi thứ đếm được
hoặc định danh được — mức nghiêm trọng, IP, cổng, PID, đường dẫn, hash, mốc
thời gian, ID, evidence ref. Model không ghi vào chúng qua bất kỳ đường nào; nó
chỉ điền vào những Ô đã khoét sẵn.

Và mỗi ô đều BỎ ĐI ĐƯỢC. Đây là phép thử: xoá sạch mọi thứ model viết, báo cáo
vẫn phải đầy đủ và vẫn dùng được. Nếu không thì model đã trở thành một phụ thuộc
vận hành, và một phụ thuộc vận hành vào một thứ có thể bịa là một lỗi thiết kế.
"""

from __future__ import annotations

import dataclasses

from shield.ai.redaction import redact_text
from shield.ai.report import (  # noqa: PLC2701
    _IPV4, _SO_NHIEU_CHU_SO, _khong_chuan_tac)
from shield.report.scenarios import (
    UNKNOWN, Scenario, explanation_allowed, for_rule)

# Bộ khung. THỨ TỰ CỐ ĐỊNH, và model không đổi được.
SECTIONS = (
    "incident_type",
    "severity",
    "time_window",
    "affected_asset",
    "observed_activity",
    "confirmed_facts",
    "validated_evidence",
    "analysis",
    "why_this_matters",
    "recommended_next_steps",
    "limitations",
)

# Trường model KHÔNG BAO GIỜ được điền. Danh sách để lộ ra đây vì nó là một
# quyết định an ninh, và có test khẳng định không ô AI nào chạm tới chúng.
DETERMINISTIC_FIELDS = frozenset({
    "severity", "risk_score", "evidence_strength", "policy_action",
    "src_ip", "dst_ip", "ip", "port", "dst_port", "pid", "process_identity",
    "exe_path", "path", "hash", "previous_hash", "current_hash",
    "first_seen", "last_seen", "ts", "window_s", "time_window",
    "incident_id", "investigation_id", "alert_id", "evidence_refs",
    "unique_ports", "failed_attempts", "count", "counts", "mac",
})

# Ô model được phép nói vào. Ba, không nhiều hơn — mỗi ô thêm là một chỗ nữa
# phải kiểm, và ba ô đã đủ để giải thích một sự cố.
AI_SLOTS = ("analysis", "hypothesis_rationale", "why_this_matters")

# Trần ký tự cho mỗi ô. Một đoạn dài hơn thế không phải giải thích, nó là văn.
MAX_SLOT_CHARS = 600

# --------------------------------------------------------------------------
# TRẠNG THÁI NHẬN THỨC — Shield biết chắc tới đâu về sự việc này.
#
# Vấn đề chất lượng lặp lại nhiều nhất khi đo model thật KHÔNG phải bịa số, mà
# là GIỌNG: "đã xác nhận sự cố", "has been confirmed to be stopped" — trong khi
# bằng chứng mới chỉ đủ để nghi ngờ. Một câu như thế vượt qua mọi phép kiểm giá
# trị, vì nó không nêu con số nào sai.
#
# Cách sai để sửa: thuê một model thứ hai chấm giọng. Cách đúng: NÓI CHO MODEL
# BIẾT Shield đang ở mức chắc chắn nào, bằng một trạng thái ĐÓNG, rồi kiểm lại
# tất định ở đường ra.
#
# Bốn trạng thái dùng lại đúng ngữ nghĩa `HYPOTHESIS_STATUS` đã có trong
# `contracts.py` — không mở một taxonomy thứ hai cho cùng một khái niệm.
CONFIRMED_FACT = "CONFIRMED_FACT"
SUPPORTED_HYPOTHESIS = "SUPPORTED_HYPOTHESIS"
UNCONFIRMED = "UNCONFIRMED"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

EPISTEMIC_STATES = (CONFIRMED_FACT, SUPPORTED_HYPOTHESIS, UNCONFIRMED,
                    INSUFFICIENT_EVIDENCE)

# Từ ngữ KHẲNG ĐỊNH ĐÃ XÁC NHẬN. Chỉ được phép khi trạng thái là
# `CONFIRMED_FACT`. Danh sách ngắn và tường minh: nó là một quyết định về nội
# dung hiển thị, không phải một bộ lọc ngôn ngữ tổng quát.
_CONFIRMATION_WORDS = (
    "confirmed", "confirms", "has been verified", "verified that", "proven",
    "proves", "definitely", "certainly", "beyond doubt",
    "đã xác nhận", "xác nhận rằng", "chắc chắn", "chứng minh", "đã chứng tỏ",
)
# Phủ định đi kèm — "not a confirmed fact" là một câu RÀO ĐÓN ĐÚNG, không phải
# một khẳng định. Bỏ qua điều này là phạt đúng hành vi ta muốn khuyến khích.
_NEGATED_CONFIRMATION = (
    "not confirmed", "not a confirmed", "cannot be confirmed", "unconfirmed",
    "not yet confirmed", "no confirmation",
    "chưa xác nhận", "không xác nhận", "chưa được xác nhận", "không phải là",
)


def epistemic_state(*, evidence_refs=(), minimum_refs: int = 1,
                    hypothesis_statuses=()) -> str:
    """Shield biết chắc tới đâu. Suy ra TẤT ĐỊNH từ dữ liệu đã có.

    Không hỏi model, không đoán: số bằng chứng đã kiểm và trạng thái giả thuyết
    do `EvidenceValidator` gán là hai thứ duy nhất quyết định.
    """
    statuses = {str(s) for s in hypothesis_statuses or ()}
    if len(evidence_refs or ()) < max(1, int(minimum_refs)):
        return INSUFFICIENT_EVIDENCE
    if "supported" in statuses:
        return SUPPORTED_HYPOTHESIS
    if statuses and statuses <= {"insufficient_evidence"}:
        return INSUFFICIENT_EVIDENCE
    # Một phát hiện tất định CÓ bằng chứng đã kiểm là một sự kiện đã xảy ra —
    # nhưng "đã xảy ra" không phải "đã hiểu vì sao". Mặc định là `UNCONFIRMED`,
    # và `CONFIRMED_FACT` chỉ dành cho chỗ gọi khẳng định được điều đó.
    return UNCONFIRMED


def allowed_values(alert: dict, evidence_refs=()) -> frozenset[str]:
    """Mọi giá trị nguyên tử ô AI ĐƯỢC PHÉP nhắc tới.

    Dựng từ chính dữ liệu chuẩn tắc của báo cáo, cùng cách
    `shield.ai.report.canonical_tokens` dựng từ `InvestigationRequest` — và
    dùng lại CHÍNH bộ nhận dạng của nó, không định nghĩa lần thứ hai.
    """
    import re as _re

    out: set[str] = {str(ref) for ref in evidence_refs or ()}
    out.add(str(alert.get("subject", "")))
    out.add(str(alert.get("severity", "")))
    out.add(str(alert.get("risk_score", "")))

    def gather(value, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, dict):
            for item in value.values():
                gather(item, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                gather(item, depth + 1)
        elif isinstance(value, bool):
            return
        elif isinstance(value, (int, float, str)):
            text = str(value)
            out.add(text)
            for part in _re.split(r"[\s,;|:]+", text):
                if not part:
                    continue
                out.add(part)
                # Một IP hay một mốc thời gian nằm lẫn trong một chuỗi lớn hơn,
                # và bộ dò coi TỪNG cụm số là một giá trị riêng: "192.168.1.77"
                # cho ra "192", "168", "77". Không thêm chúng vào tập cho phép
                # thì một câu ĐÚNG nhắc đúng IP trong dữ liệu vẫn bị bỏ — đã
                # xảy ra, và bài đối chứng bắt được.
                out.update(_IPV4.findall(part))
                out.update(_SO_NHIEU_CHU_SO.findall(part))

    gather(alert.get("evidence") or {})
    gather(alert.get("first_seen"))
    gather(alert.get("last_seen"))
    return frozenset(out)


def asserts_confirmation(text: str) -> bool:
    """Câu này có khẳng định "đã xác nhận" không, sau khi trừ phủ định."""
    lowered = str(text or "").lower()
    if not any(word in lowered for word in _CONFIRMATION_WORDS):
        return False
    return not any(mark in lowered for mark in _NEGATED_CONFIRMATION)


def clean_prose(value, *, state: str = UNCONFIRMED,
                allowed: "frozenset[str] | None" = None,
                max_chars: int = MAX_SLOT_CHARS) -> str:
    """Một đoạn văn model viết -> đoạn AN TOÀN, hoặc chuỗi rỗng.

    ĐÂY LÀ CỬA DUY NHẤT. Mọi văn xuôi do model sinh — ô báo cáo, câu trả lời
    chat, bất cứ thứ gì thêm sau này — phải đi qua đúng hàm này. Lý do không
    phải gọn gàng: dự án này đã ba lần có hai cổng cho cùng một câu hỏi, và cả
    ba lần chúng lệch nhau theo hướng cái yếu hơn thắng. Một bản sao "gần
    giống" của bộ kiểm dưới đây là một lỗ hổng có hẹn giờ.

    Bỏ CẢ ĐOẠN chứ không vá từng câu: một đoạn bị vá nửa vời vẫn đọc như một
    đoạn do người viết, và đó chính là thứ làm nó thuyết phục.
    """
    text = str(value or "").replace("\x00", "").strip()
    if not text:
        return ""
    if state != CONFIRMED_FACT and asserts_confirmation(text):
        # Model nói "đã xác nhận" trong khi Shield chưa xác nhận gì.
        return ""
    if allowed is not None and _khong_chuan_tac(text, allowed):
        # Đoạn văn nêu một con số hoặc định danh KHÔNG có trong dữ liệu chuẩn
        # tắc. Đo được trên model thật: với một sự cố SSH không có trường
        # `port`, model vẫn viết "on port 22" — một chi tiết hợp lý, sai, và
        # không ai đọc ra được là sai.
        return ""
    return redact_text(text[:max_chars])


@dataclasses.dataclass(frozen=True)
class AiSlots:
    """Thứ model được phép đóng góp. Rỗng là hợp lệ và phải luôn hợp lệ."""

    analysis: str = ""
    hypothesis_rationale: str = ""
    why_this_matters: str = ""

    def cleaned(self, *, state: str = UNCONFIRMED,
                allowed: frozenset[str] | None = None) -> dict:
        """Đã cắt trần, đã che bí mật, và đã BỎ ô khẳng định quá tay.

        Bỏ CẢ Ô chứ không vá từng câu, cùng lý do như 3A: một đoạn bị vá nửa
        vời vẫn đọc như một đoạn do người viết, và đó chính là thứ làm nó
        thuyết phục. Ô rỗng thì báo cáo vẫn đầy đủ — đó là điều kiện của cả
        thiết kế này.
        """
        return {name: clean_prose(getattr(self, name, ""), state=state,
                                  allowed=allowed, max_chars=MAX_SLOT_CHARS)
                for name in AI_SLOTS}

    @classmethod
    def from_result(cls, result) -> "AiSlots":
        """Lấy ô từ một `InvestigationResult` ĐÃ qua `OutputValidator`.

        Đọc `summary` sau khi nó đã bị kiểm: nếu model bịa một con số, tầng 3A
        đã xoá cả đoạn và `summary` rỗng — nên ô ở đây rỗng theo, và báo cáo
        vẫn đầy đủ. Không có đường nào để văn xuôi chưa kiểm đi vào.
        """
        if result is None:
            return cls()
        rationale = ""
        for hypothesis in getattr(result, "hypotheses", ()) or ():
            statement = getattr(hypothesis, "statement", "")
            # `—` là chỗ giữ chỗ 3A đặt khi nó bỏ một câu bịa số.
            if statement and statement != "—":
                rationale = statement
                break
        return cls(analysis=getattr(result, "summary", "") or "",
                   hypothesis_rationale=rationale)


def classify(alert: dict) -> tuple[str, str]:
    """-> (scenario_code, nguồn quyết định). THUẦN TẤT ĐỊNH.

    Model KHÔNG tham gia. Nó từng được phép đề xuất khi Shield chưa có ánh xạ;
    đo trên model thật cho 54,8% scenario accuracy trong khi một dòng registry
    cho 100%, và tập `rule_id` là ĐÓNG và biết trước lúc build. Đoán một thứ
    đếm được là thêm sai số không đổi lấy gì.

    Ưu tiên định danh, theo đúng ngữ nghĩa sẵn có của Shield:

    1. `rule_id` — báo cáo cho một alert cụ thể.
    2. `correlation_id` — báo cáo mức incident. Đây CHÍNH LÀ `rule_id` của quy
       tắc tương quan đã sinh ra incident, nên nó tra cùng một bảng; không có
       heuristic nào được phát minh ở đây.
    3. `UNKNOWN`.
    """
    for key in ("rule_id", "correlation_id"):
        value = str(alert.get(key, "") or "")
        if not value:
            continue
        canonical = for_rule(value)
        if canonical is not None:
            return canonical.scenario_code, "canonical"
    return UNKNOWN, "unknown"


def _facts(alert: dict, scenario: Scenario | None) -> tuple[dict, list[str]]:
    """Dữ kiện chuẩn tắc cho khuôn, và những trường bắt buộc còn THIẾU.

    Thiếu thì NÓI ra, không bịa và không im lặng bỏ mục: một báo cáo im lặng bỏ
    "failed_attempts" đọc y hệt một báo cáo mà con số đó bằng không.
    """
    evidence = alert.get("evidence") or {}
    facts, missing = {}, []
    if scenario is None:
        return facts, missing
    for key in scenario.required_fact_keys:
        if key in evidence and evidence[key] not in (None, ""):
            facts[key] = evidence[key]
        else:
            missing.append(key)
    for key in scenario.optional_fact_keys:
        if key in evidence and evidence[key] not in (None, ""):
            facts[key] = evidence[key]
    return facts, missing


def render(alert: dict, *, scenario_code: str = "", source: str = "canonical",
           evidence_refs=(), slots: AiSlots | None = None,
           locale: str = "vi", state: str = "") -> dict:
    """Một báo cáo sự cố. Tất định trừ ba ô, và ba ô đó bỏ được.

    `alert` là dữ liệu chuẩn tắc của Shield (`Alert.to_dict()`-shape). Mọi giá
    trị đếm được hay định danh được trong kết quả đến TỪ ĐÂY, không từ model.
    """
    from shield.report.scenarios import BY_CODE

    code = scenario_code or UNKNOWN
    scenario = BY_CODE.get(code)
    facts, missing = _facts(alert, scenario)
    refs_now = tuple(evidence_refs or ())
    resolved_state = state or epistemic_state(
        evidence_refs=refs_now,
        minimum_refs=scenario.minimum_evidence_refs if scenario else 1)
    # Họ không đủ điều kiện -> KHÔNG có văn xuôi AI, bất kể model nói gì.
    # Cổng nằm ở registry chính danh, không ở giao diện.
    if not explanation_allowed(code):
        slots = None
    ai = (slots or AiSlots()).cleaned(
        state=resolved_state, allowed=allowed_values(alert, refs_now))

    refs = sorted({str(ref) for ref in (evidence_refs or ()) if str(ref)})
    limitations = []
    if missing:
        limitations.append({"key": "report.limitation.missing_facts",
                            "params": {"fields": ", ".join(sorted(missing))}})
    if scenario is not None and len(refs) < scenario.minimum_evidence_refs:
        limitations.append({"key": "report.limitation.thin_evidence",
                            "params": {"have": len(refs),
                                       "need": scenario.minimum_evidence_refs}})
    if code == UNKNOWN:
        limitations.append({"key": "report.limitation.unknown_scenario", "params": {}})
    if not any(ai.values()):
        limitations.append({"key": "report.limitation.no_ai_explanation", "params": {}})

    return {
        "schema_version": 1,
        "locale": locale,
        # --- mục 1–2: kịch bản và mức nghiêm trọng, CẢ HAI tất định ---
        "epistemic_state": resolved_state,
        "explanation_eligible": explanation_allowed(code),
        "incident_type": {
            "scenario_code": code,
            "family": scenario.family if scenario else UNKNOWN,
            "rule_id": str(alert.get("rule_id", "")),
            "template_key": scenario.template_key() if scenario else "report.template.generic",
            # Ai quyết định phân loại này. Người đọc phải phân biệt được một
            # ánh xạ tất định với một đề xuất của model.
            "classified_by": source,
        },
        # Model KHÔNG BAO GIỜ đặt trường này. Nó đến từ detector.
        "severity": {"level": str(alert.get("severity", "info")),
                     "risk_score": int(alert.get("risk_score", 0) or 0),
                     "evidence_strength": float(alert.get("evidence_strength", 0.0) or 0.0)},
        "time_window": {"first_seen": float(alert.get("first_seen", alert.get("ts", 0.0)) or 0.0),
                        "last_seen": float(alert.get("last_seen", alert.get("ts", 0.0)) or 0.0)},
        "affected_asset": {"subject": str(alert.get("subject", ""))},
        "observed_activity": {"title": str(alert.get("title", "")),
                              "detail": str(alert.get("detail", ""))},
        # --- mục 6–7: dữ kiện và bằng chứng, thuần tất định ---
        "confirmed_facts": facts,
        "missing_required_facts": sorted(missing),
        "validated_evidence": {"refs": refs, "count": len(refs)},
        # --- mục 8–9: Ô CỦA MODEL. Rỗng là hợp lệ. ---
        "analysis": {"prose": ai["analysis"],
                     "hypothesis_rationale": ai["hypothesis_rationale"],
                     "ai_generated": bool(ai["analysis"] or ai["hypothesis_rationale"])},
        "why_this_matters": {"prose": ai["why_this_matters"],
                             "ai_generated": bool(ai["why_this_matters"])},
        # --- mục 10–11: hành động và giới hạn, tất định ---
        "recommended_next_steps": {
            # CHỈ ID trong allowlist của kịch bản, giao nhau với playbook của
            # alert. Model không thêm được một bước nào.
            "codes": sorted(set(scenario.allowed_recommendation_codes if scenario
                                else ("snapshot_state",))
                            & set(alert.get("playbook") or ("snapshot_state",))
                            or {"snapshot_state"}),
        },
        "limitations": limitations,
        # Mục nào là dữ liệu, mục nào là câu. Giao diện dịch phần thứ hai.
        "deterministic_sections": [s for s in SECTIONS
                                   if s not in ("analysis", "why_this_matters")],
        "ai_sections": ["analysis", "why_this_matters"],
    }


def strip_ai(report: dict) -> dict:
    """Báo cáo với MỌI ô AI bỏ trống. Phép thử "bỏ được mà vẫn đầy đủ".

    Dùng trong test, và dùng thật khi kill switch bật hoặc model không trả lời:
    người dùng vẫn nhận đúng bản báo cáo đó, chỉ thiếu phần giải thích.
    """
    out = dict(report)
    out["analysis"] = {"prose": "", "hypothesis_rationale": "", "ai_generated": False}
    out["why_this_matters"] = {"prose": "", "ai_generated": False}
    limitations = [item for item in out.get("limitations", [])
                   if item.get("key") != "report.limitation.no_ai_explanation"]
    limitations.append({"key": "report.limitation.no_ai_explanation", "params": {}})
    out["limitations"] = limitations
    return out
