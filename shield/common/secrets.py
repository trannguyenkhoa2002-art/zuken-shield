"""Định nghĩa DUY NHẤT về "cái gì là bí mật".

Trước file này có hai bộ luật che: một ở đường đọc (`evidence/queries.py`) và
một ở đường gửi đi (`ai/redaction.py`). Chúng lệch nhau, và bộ yếu hơn được
dùng ở đúng chỗ nhật ký lời gọi tool — nên khoá AWS, token GitHub, token Slack
và `password=...` trong một trường tên vô hại đều lọt vào nhật ký.

Hai bộ luật cho cùng một khái niệm là hai câu trả lời khác nhau cho cùng một
câu hỏi, và câu trả lời được dùng sẽ là câu nào tình cờ được import.
"""

from __future__ import annotations

import re

REDACTED = "[đã che]"

# Tên khoá mà giá trị không bao giờ được hiển thị. So khớp theo TÊN vì tên thì
# chắc chắn; "chuỗi này trông giống token" là trò chơi không bao giờ thắng.
SECRET_KEYS = re.compile(
    r"pass|passwd|password|secret|token|api[_-]?key|apikey|authorization|"
    r"cookie|session[_-]?id|private[_-]?key|privkey|psk|credential|otp",
    re.IGNORECASE,
)

# Giá trị rõ ràng là bí mật dù khoá vô hại. Danh sách CỐ Ý hẹp: che quá nhiều
# thì mất nội dung điều tra, và một công cụ che quá nhiều sẽ bị tắt đi.
SECRET_VALUES = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)

# `khoá=giá trị` trong một dòng log tự do. Che phần GIÁ TRỊ, giữ phần tên —
# biết "có một password ở đây" là thông tin điều tra; biết nó là gì thì không.
INLINE_ASSIGNMENT = re.compile(
    r"(?i)\b((?:pass|passwd|password|token|secret|api[_-]?key|authorization)\w*)"
    r"(\s*[=:]\s*)(\S+)"
)

MAX_DEPTH = 12


def redact_text(value: str) -> str:
    text = str(value)
    for pattern in SECRET_VALUES:
        if pattern.search(text):
            return REDACTED
    return INLINE_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


def redact(value, _depth: int = 0):
    """Che đệ quy. Cấu trúc lồng quá sâu bị cắt thay vì tràn ngăn xếp."""
    if _depth > MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            key: (REDACTED if SECRET_KEYS.search(str(key)) else redact(item, _depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def contains_secret(payload) -> bool:
    """Còn sót bí mật nào không. Hỏi TRƯỚC khi gửi thì rẻ; hỏi sau thì vô nghĩa."""
    import json

    text = json.dumps(payload, ensure_ascii=False, default=str)
    return any(pattern.search(text) for pattern in SECRET_VALUES)
