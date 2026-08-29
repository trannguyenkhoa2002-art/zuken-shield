"""Kiểm MÃ NGUỒN, không kiểm tài liệu — dùng chung.

Tìm chuỗi thô trong file nguồn làm chính đoạn giải thích "không bao giờ dùng X"
khiến bài test đỏ, và cách sửa rẻ nhất khi ấy là xoá lời giải thích — tức là
bài test trừng phạt đúng thứ đáng giữ. Đã mắc hai lần (3C-0 và 3C); đây là bản
dùng chung để không mắc lần thứ ba.
"""

from __future__ import annotations

import io
import tokenize


def code_only(path: str) -> str:
    """Nguồn đã bỏ mọi chú thích và chuỗi (gồm cả docstring)."""
    kept = []
    with open(path, "rb") as handle:
        for token in tokenize.tokenize(io.BytesIO(handle.read()).readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            kept.append(token.string)
    return " ".join(kept)
