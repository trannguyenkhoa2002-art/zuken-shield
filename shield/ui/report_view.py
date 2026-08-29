"""Dựng nội dung màn hình báo cáo sự cố — THUẦN, không chạm Qt.

Cùng lý do như `incident_view.py` và `evidence_view.py`: máy CI không import
được PySide6, mà những chỗ dễ sai nhất ở đây lại kiểm được hoàn toàn không cần
Qt — thứ tự mục, khoá dịch, trạng thái "chưa có dữ liệu", và quan trọng nhất:
ranh giới giữa DỮ LIỆU CỦA SHIELD và VĂN XUÔI CỦA MODEL.

Ranh giới đó là bất biến của cả file. Hai loại nội dung này có mức đáng tin
khác hẳn nhau:

- `deterministic`: Shield đo được. Con số, định danh, mốc thời gian.
- `ai`: model viết. Đã qua kiểm, nhưng vẫn là diễn giải, và luôn PHỤ.

Trộn chúng vào một khối là cách nhanh nhất để một suy đoán được đọc như một sự
thật — và đó là lỗi mà mọi lớp phía dưới đã bỏ công để tránh. Ở đây chúng đi ra
thành HAI danh sách riêng, và giao diện không có cách nào nối chúng lại.
"""

from __future__ import annotations

# Thứ tự mục. CỐ ĐỊNH, và không phụ thuộc model: người trực đọc báo cáo thứ
# hai mươi lúc 3 giờ sáng phải biết "bước tiếp theo" nằm ở đâu mà không đọc lại
# từ đầu.
SECTION_ORDER = (
    "incident_type", "severity", "time_window", "affected_asset",
    "observed_activity", "confirmed_facts", "validated_evidence",
    "supporting_detections", "recommended_next_steps", "limitations",
)

# Trạng thái làm giàu -> khoá dịch. ĐÓNG: một trạng thái lạ không được hiện ra
# thành chuỗi thô cho người dùng đọc.
STATUS_KEYS = {
    "disabled": "report.ai.state.disabled",
    "ineligible": "report.ai.state.ineligible",
    "pending": "report.ai.state.pending",
    "ready": "report.ai.state.ready",
    "failed": "report.ai.state.failed",
    "deferred": "report.ai.state.deferred",
}

# Trạng thái nào còn đáng hỏi lại. Ngoài hai cái này thì DỪNG — hỏi mãi một
# câu đã có câu trả lời cuối cùng là đốt CPU của chính máy đang được bảo vệ.
POLLABLE = frozenset({"pending"})


def deterministic_rows(report: dict, translate, format_ts) -> list[tuple[str, str, str]]:
    """(khoá_nhãn, giá_trị_hiển_thị, mục). KHÔNG có gì do model sinh ra."""
    if not report:
        return [("report.empty", "", "incident_type")]

    incident = report.get("incident_type") or {}
    severity = report.get("severity") or {}
    window = report.get("time_window") or {}
    rows: list[tuple[str, str, str]] = [
        ("report.field.scenario",
         translate(incident.get("template_key", "report.template.generic")),
         "incident_type"),
        ("report.field.family", str(incident.get("family", "") or "—"), "incident_type"),
        ("report.field.rule", str(incident.get("rule_id", "") or "—"), "incident_type"),
        ("report.field.severity", str(severity.get("level", "") or "—"), "severity"),
        ("report.field.risk", str(severity.get("risk_score", 0)), "severity"),
        ("report.field.first_seen", format_ts(window.get("first_seen", 0)), "time_window"),
        ("report.field.last_seen", format_ts(window.get("last_seen", 0)), "time_window"),
        ("report.field.subject",
         str((report.get("affected_asset") or {}).get("subject", "") or "—"),
         "affected_asset"),
    ]

    facts = report.get("confirmed_facts") or {}
    if facts:
        for key in sorted(facts):
            rows.append((f"report.fact.{key}", _render(facts[key]), "confirmed_facts"))
    else:
        rows.append(("report.no_facts", "", "confirmed_facts"))
    for missing in report.get("missing_required_facts") or ():
        rows.append(("report.missing_fact", str(missing), "confirmed_facts"))

    evidence = report.get("validated_evidence") or {}
    refs = list(evidence.get("refs") or ())
    if refs:
        for ref in refs:
            rows.append(("report.evidence_ref", str(ref), "validated_evidence"))
    else:
        rows.append(("report.no_evidence", "", "validated_evidence"))

    for detection in report.get("supporting_detections") or ():
        rows.append((
            "report.supporting",
            f"{detection.get('rule_id', '')} · {detection.get('severity', '')} · "
            f"{format_ts(detection.get('ts', 0))}",
            "supporting_detections"))

    for code in (report.get("recommended_next_steps") or {}).get("codes", ()):
        rows.append((f"report.action.{code}", str(code), "recommended_next_steps"))

    for item in report.get("limitations") or ():
        rows.append((item.get("key", ""),
                     translate(item.get("key", "")).format(**(item.get("params") or {}))
                     if item.get("key") else "", "limitations"))
    return rows


def ai_rows(report: dict, state: dict, translate) -> list[tuple[str, str]]:
    """(khoá_nhãn, văn xuôi) cho ba ô — hoặc rỗng.

    Trả về danh sách RIÊNG, không trộn vào `deterministic_rows`. Giao diện vẽ
    chúng ở một khối phụ, có nhãn nói rõ đây là văn do model viết.
    """
    if str(state.get("status", "")) != "ready":
        return []
    analysis = report.get("analysis") or {}
    matters = report.get("why_this_matters") or {}
    rows = []
    for key, value in (("report.ai.analysis", analysis.get("prose", "")),
                       ("report.ai.rationale", analysis.get("hypothesis_rationale", "")),
                       ("report.ai.matters", matters.get("prose", ""))):
        text = str(value or "").strip()
        if text:
            rows.append((key, text))
    return rows


def status_line(state: dict, translate) -> str:
    """Một dòng ngắn, đã dịch. Không bao giờ là câu ngoại lệ thô.

    Trạng thái lạ rơi về `deferred` thay vì hiện ra chuỗi thô: người dùng không
    đọc mã lỗi của ta, và một chuỗi lạ trên màn hình chỉ nói rằng có gì đó ta
    không lường trước — điều đó thuộc về nhật ký, không thuộc về báo cáo.
    """
    status = str(state.get("status", "")) or "deferred"
    key = STATUS_KEYS.get(status, STATUS_KEYS["deferred"])
    return translate(key)


def should_poll(state: dict) -> bool:
    """Còn đáng hỏi lại không. Chỉ `pending`."""
    return str(state.get("status", "")) in POLLABLE


def evidence_refs(report: dict) -> list[str]:
    """Ref bằng chứng để mở màn hình Expert Evidence ĐÃ CÓ.

    Không dựng màn hình bằng chứng thứ hai: `evidence_view` đã biết cách hiện
    một sự kiện, gồm cả câu trả lời khi Shield không giữ payload gốc.
    """
    return [str(ref) for ref in
            ((report.get("validated_evidence") or {}).get("refs") or ()) if ref]


def _render(value) -> str:
    """Giá trị -> chuỗi hiển thị. KHÔNG dịch: đây là dữ liệu, không phải câu."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value) if value not in (None, "") else "—"
