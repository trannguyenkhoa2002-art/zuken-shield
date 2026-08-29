"""Che bí mật trên đường GỬI ĐI (mục 5.2).

Luật nằm ở `shield.common.secrets` — một nguồn sự thật duy nhất dùng chung với
đường đọc. Hai bộ luật cho cùng một khái niệm là hai câu trả lời khác nhau cho
cùng một câu hỏi, và câu được dùng sẽ là câu nào tình cờ được import. Đó đã là
một lỗi thật: nhật ký lời gọi tool dùng bộ yếu hơn, nên khoá AWS, token GitHub
và `password=...` trong một trường tên vô hại đều lọt vào nhật ký.
"""

from __future__ import annotations

from shield.common.secrets import (
    INLINE_ASSIGNMENT,
    MAX_DEPTH,
    REDACTED,
    SECRET_KEYS,
    SECRET_VALUES,
    contains_secret,
    redact,
    redact_text,
)

__all__ = ["INLINE_ASSIGNMENT", "MAX_DEPTH", "REDACTED", "SECRET_KEYS", "SECRET_VALUES",
           "contains_secret", "redact", "redact_text"]
