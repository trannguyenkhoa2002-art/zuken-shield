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
        str(entry.get("reason", "")),
        "; ".join(missing) if missing else "—",
    ]
