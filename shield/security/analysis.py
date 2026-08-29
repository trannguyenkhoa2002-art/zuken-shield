"""Read-only, offline-first security analysis.

This module deliberately has no response/action dependency. Analyzer output is
plain text and structured observations only.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass

from shield.common.secrets import REDACTED, SECRET_KEYS
from shield.common.secrets import redact_text as _redact_text

# Trần bộ nhớ, KHÔNG phải luật che. Một bản ghi bất thường không được biến
# thành một chuỗi vài chục MB trong bản tóm tắt.
MAX_ITEMS = 100
MAX_STRING = 4096


def redact(value, key: str = ""):
    """Che bí mật theo luật CHUNG ở `shield/common/secrets.py`.

    Trước đây hàm này có bộ luật riêng: 5 tên khoá và đúng một regex `bearer`.
    Nó bỏ lọt khoá AWS, token GitHub, token Slack, khoá riêng PEM, JWT và
    `API_KEY=...` trong dòng lệnh — mà `LocalSummaryAnalyzer` thì chạy trên
    bản ghi thật. Đây là lần thứ hai hai bộ luật che cùng tồn tại trong repo
    này; lần trước bộ yếu hơn nằm ở nhật ký lời gọi tool.

    Tham số `key` giữ lại cho tương thích: khi biết tên trường thì so theo tên
    chắc chắn hơn là đoán từ giá trị.
    """
    if key and SECRET_KEYS.search(str(key)):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value[:MAX_ITEMS]]
    if isinstance(value, str):
        # Che TRƯỚC rồi mới cắt: cắt trước thì một bí mật dài có thể mất phần
        # đuôi và không còn khớp mẫu nào nữa.
        return _redact_text(value)[:MAX_STRING]
    return value


@dataclass(frozen=True)
class AnalysisResult:
    engine: str
    summary: str
    observations: tuple[str, ...]
    record_count: int
    offline: bool = True


class LocalSummaryAnalyzer:
    """Tiny deterministic analyzer: no model, network, GPU or subprocess."""
    name = "local-summary-v1"

    async def analyze(self, records: list[dict], lang: str = "en") -> AnalysisResult:
        clean = [redact(record) for record in records[:2000]]
        severity = collections.Counter(str(r.get("severity", "unknown")) for r in clean)
        rules = collections.Counter(str(r.get("rule_id", "unknown")) for r in clean)
        subjects = collections.Counter(str(r.get("subject", "unknown")) for r in clean)
        top_rules = ", ".join(f"{rule} ({count})" for rule, count in rules.most_common(3)) or "none"
        summary = (
            f"Đã phân tích {len(clean)} bản ghi cục bộ: {severity.get('critical', 0)} nguy cấp, "
            f"{severity.get('warning', 0)} cảnh báo, {severity.get('info', 0)} thông tin. "
            f"Rule xuất hiện nhiều nhất: {top_rules}."
            if lang == "vi" else
            f"Analyzed {len(clean)} local records: {severity.get('critical', 0)} critical, "
            f"{severity.get('warning', 0)} warning, {severity.get('info', 0)} info. "
            f"Most frequent rules: {top_rules}."
        )
        observations = []
        if severity.get("critical", 0):
            observations.append(
                "Có phát hiện nguy cấp; hãy xem evidence và timeline trước khi phản ứng."
                if lang == "vi" else
                "Critical findings exist; review evidence and timeline before responding."
            )
        if subjects:
            subject, count = subjects.most_common(1)[0]
            observations.append(
                f"Đối tượng xuất hiện nhiều nhất: {subject} ({count} phát hiện)."
                if lang == "vi" else f"Most frequent subject: {subject} ({count} findings)."
            )
        if not clean:
            observations.append(
                "Không có bản ghi trong khoảng thời gian đã chọn."
                if lang == "vi" else "No records were available for the selected period."
            )
        return AnalysisResult(self.name, summary, tuple(observations), len(clean), True)
