"""Dữ liệu hiển thị của tab Vùng xám — hàm thuần, không cần Qt để kiểm thử."""

from __future__ import annotations

import time

from shield.security.evidence_model import fact_label

KIND_LABEL = {
    "below_threshold": ("Chưa tới ngưỡng", "Below threshold"),
    "low_confidence": ("Thiếu bằng chứng", "Low evidence confidence"),
    "suppressed": ("Đã tắt tiếng", "Suppressed by policy"),
}
COLUMNS = (
    ("Lần cuối", "Last seen"), ("Loại", "Kind"), ("Rule", "Rule"), ("Đối tượng", "Subject"),
    ("Rủi ro", "Risk"), ("Tin cậy", "Confidence"), ("Số lần", "Count"), ("Lý do", "Reason"),
    ("Còn thiếu", "Missing evidence"),
)


def _pick(pair: tuple[str, str], lang: str) -> str:
    return pair[0] if lang == "vi" else pair[1]


def headers(lang: str) -> list[str]:
    return [_pick(column, lang) for column in COLUMNS]


def reason_text(entry: dict, lang: str) -> str:
    """Lý do, dựng từ DỮ LIỆU theo ngôn ngữ đang chọn — không dùng câu tiếng Anh
    agent ghi sẵn (UI tiếng Việt từng hiện "3 failed logins, threshold is 5")."""
    kind = str(entry.get("kind"))
    near = (entry.get("evidence") or {}).get("gray_zone") or {}
    if kind == "below_threshold" and "observed" in near and "threshold" in near:
        return _pick((f"{near['observed']}/{near['threshold']} — chưa tới ngưỡng phát hiện",
                      f"{near['observed']}/{near['threshold']} — below the detection threshold"), lang)
    if kind == "low_confidence":
        risk, conf = int(entry.get("risk_score", 0)), int(entry.get("evidence_confidence", -1))
        return _pick((f"Rủi ro {risk}/100 nhưng độ tin cậy bằng chứng chỉ {conf}/100",
                      f"Risk {risk}/100 but evidence confidence only {conf}/100"), lang)
    if kind == "suppressed":
        raw = str(entry.get("reason", ""))
        policy = raw.split(":", 1)[1].strip() if ":" in raw else raw
        return _pick((f"Bị policy tắt tiếng: {policy}", f"Suppressed by policy: {policy}"), lang)
    return str(entry.get("reason", ""))


def row_values(entry: dict, lang: str) -> list[str]:
    confidence = int(entry.get("evidence_confidence", -1))
    missing = [fact_label(str(entry.get("rule_id", "")), str(f), lang) for f in entry.get("missing") or ()]
    return [
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(entry.get("last_seen", 0)))),
        _pick(KIND_LABEL.get(str(entry.get("kind")), (str(entry.get("kind")),) * 2), lang),
        str(entry.get("rule_id", "")),
        str(entry.get("subject", "")),
        f"{int(entry.get('risk_score', 0))}/100",
        f"{confidence}/100" if confidence >= 0 else "—",
        str(int(entry.get("count", 1))),
        reason_text(entry, lang),
        "; ".join(missing) if missing else "—",
    ]
