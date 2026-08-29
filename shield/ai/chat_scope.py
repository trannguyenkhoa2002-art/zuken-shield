"""Câu hỏi nào KHÔNG cần model. Quyết định tất định, trước mọi lượt suy luận.

Hai loại đi thẳng ra câu trả lời cố định:

1. Yêu cầu HÀNH ĐỘNG ("cách ly máy này", "chặn IP"). Chat v0 không thực thi gì,
   và hỏi model để nó nói "việc này ngoài phạm vi" là trả 25 giây cùng một rủi
   ro bịa đặt để nhận về một câu ta đã biết trước.
2. Câu hỏi ngoài phạm vi sự cố ("thời tiết thế nào", "viết hộ đoạn Python").

Nhận diện hành động dựa trên `ACTION_SPECS` — cùng bảng mà tầng quyết định
dùng — chứ không phải một danh sách từ khoá tự nghĩ ra. Thêm một hành động mới
vào sản phẩm là tự động thêm nó vào đây, và một danh sách rời sẽ lệch ngay lần
đổi đầu tiên.
"""

from __future__ import annotations

import re
import unicodedata

from shield.decision.models import ACTION_SPECS

OUT_OF_SCOPE = "out_of_scope"
ACTION_REQUEST = "action_request"
IN_SCOPE = "in_scope"

# Từ ngữ tự nhiên cho mỗi mã hành động, hai ngôn ngữ. KHÓA là mã trong
# `ACTION_SPECS`; một mã mới mà quên khai ở đây sẽ bị test bắt.
_ACTION_WORDS: dict[str, tuple[str, ...]] = {
    "block_ip": ("block ip", "block the ip", "chan ip", "chan dia chi"),
    "isolate_endpoint": ("isolate", "isolate host", "cach ly", "ngat mang",
                         "cat mang"),
    "rate_limit_ip": ("rate limit", "gioi han toc do", "bop bang thong"),
    "snapshot_state": ("snapshot", "chup trang thai"),
    "stop_process": ("stop process", "kill process", "dung tien trinh",
                     "giet tien trinh", "tat tien trinh"),
    "alert": (),
}

# Động từ ra lệnh: "hãy chạy", "run", "execute". Một câu hỏi VỀ hành động
# ("cách ly có nghĩa là gì?") không phải một yêu cầu thực thi, nên chỉ mã hành
# động thôi là chưa đủ — xem `classify`.
_IMPERATIVES = ("hay ", "lam on ", "run ", "execute ", "chay ", "thuc hien ",
                "please ", "do ", "now", "ngay", "giup toi ", "toi muon ")

# Việc Shield CHẠY ĐƯỢC nhưng không nằm trong `ACTION_SPECS` (đó là bảng của
# tầng quyết định, không phải mọi thao tác). Giữ NGẮN và có lý do: mỗi mục ở
# đây là một thứ người dùng có thể tưởng chat làm hộ được.
_RUN_REQUESTS = ("scan", "quet lai", "quet them", "pcap", "bat goi tin",
                 "snapshot lai", "shell", "lenh he thong")

_QUESTION_ABOUT = ("nghia la gi", "la gi", "what does", "what is", "y nghia",
                   "co nghia", "explain", "giai thich")

# Chủ đề rõ ràng không thuộc về một sự cố bảo mật trên máy này.
_OFF_TOPIC = (
    "thoi tiet", "weather", "viet ho", "write me", "write a", "python",
    "javascript", "cong thuc nau", "recipe", "dich sang", "translate this",
    "joke", "ke chuyen", "tho ", "poem", "bitcoin", "gia vang", "stock",
    "who are you", "ban la ai", "system prompt", "prompt he thong",
    "may khac", "another machine", "other host", "may chu khac",
)


def _fold(text: str) -> str:
    """Bỏ dấu, hạ chữ thường. So khớp không phụ thuộc cách gõ tiếng Việt."""
    lowered = str(text or "").lower().strip()
    stripped = unicodedata.normalize("NFD", lowered)
    stripped = "".join(ch for ch in stripped if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", stripped.replace("đ", "d"))


def action_codes(question: str) -> tuple[str, ...]:
    """Mã hành động được nhắc tới trong câu hỏi. Rỗng nếu không có."""
    folded = _fold(question)
    found = []
    for code, words in _ACTION_WORDS.items():
        if code not in ACTION_SPECS:
            continue
        if any(word and word in folded for word in words):
            found.append(code)
    return tuple(sorted(found))


def classify(question: str) -> str:
    """-> `IN_SCOPE` | `ACTION_REQUEST` | `OUT_OF_SCOPE`. THUẦN, không I/O."""
    folded = _fold(question)
    if not folded:
        return IN_SCOPE
    if any(topic in folded for topic in _OFF_TOPIC):
        return OUT_OF_SCOPE
    if any(word in folded for word in _RUN_REQUESTS) and any(
            verb in folded for verb in _IMPERATIVES):
        return ACTION_REQUEST
    codes = action_codes(folded)
    if codes:
        # "Cách ly nghĩa là gì?" là một câu hỏi; "hãy cách ly máy" là một lệnh.
        # Phân biệt được thì người dùng vẫn hỏi được về hành động mà không bị
        # trả lời cụt.
        if any(mark in folded for mark in _QUESTION_ABOUT):
            return IN_SCOPE
        if any(verb in folded for verb in _IMPERATIVES) or folded.startswith(codes[0][:5]):
            return ACTION_REQUEST
        return ACTION_REQUEST
    return IN_SCOPE
