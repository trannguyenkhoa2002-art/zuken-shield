"""Câu người dùng gõ -> MỘT ý định đóng. TẤT ĐỊNH, không hỏi model.

Đây là chỗ dễ sa vào cám dỗ nhất của cả tính năng: model đang chạy sẵn, và nhờ
nó phân loại câu hỏi trông rẻ hơn nhiều so với viết luật. Phép thử đó đã chạy
rồi, ở tầng kịch bản — model đạt 54,8% còn bảng tra tất định đạt 100%, và kết
luận khi ấy là bỏ hẳn vai trò phân loại của model. Không có lý do gì để nó khác
đi ở đây; chỉ có lý do để quên mất.

Luật: bỏ dấu, hạ chữ, rồi so cụm. Cụm được chọn theo NGHĨA chứ không theo từ
đơn — "process" một mình xuất hiện trong cả "process nào liên quan" lẫn "giải
thích process_exec", nên từ đơn sẽ ánh xạ sai.
"""

from __future__ import annotations

from shield.ai.chat_intents import (CERTAINTY, EVIDENCE_EXPLANATION,
                                    INCIDENT_SUMMARY, NEXT_INVESTIGATION_STEP,
                                    OUT_OF_SCOPE_CHAT, RELATED_PROCESS)
from shield.ai.chat_scope import ACTION_REQUEST, OUT_OF_SCOPE, _fold, classify

# Thứ tự QUAN TRỌNG: cụm đặc trưng nhất đứng trước. "điều gì chưa được xác
# nhận" phải về CERTAINTY chứ không về EVIDENCE_EXPLANATION dù có chữ "gì".
_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (CERTAINTY, (
        "co chac", "chac chan chua", "chac khong", "co the ket luan",
        "da bi compromise chua", "bi chiem quyen chua", "muc do chac chan",
        "do tin cay", "chua duoc xac nhan", "chua xac nhan", "gioi han",
        "how certain", "are you sure", "how confident", "confirmed yet",
        "what is unconfirmed", "not confirmed", "limitation", "certainty",
        "confidence", "confirmed compromis", "bi chiem quyen khong",
    )),
    (NEXT_INVESTIGATION_STEP, (
        "kiem tra gi tiep", "lam gi tiep", "buoc tiep theo", "nen kiem tra",
        "nen lam gi", "toi nen xem gi", "tiep theo nen", "dieu tra tiep",
        "what should i", "what next", "next step", "what to check",
        "how should i investigate", "recommend",
    )),
    (RELATED_PROCESS, (
        "process nao", "tien trinh nao", "process lien quan",
        "tien trinh lien quan", "tien trinh dang chu y", "process dang chu y",
        "pid nao", "which process", "what process", "processes involved",
        "related process",
    )),
    (EVIDENCE_EXPLANATION, (
        "bang chung nao", "bang chung gi", "dua vao dau", "co so nao",
        "tai sao shield", "vi sao shield", "tai sao canh bao", "vi sao canh bao",
        "giai thich bang chung", "ho tro ket luan", "chung minh",
        "which evidence", "what evidence", "why did shield", "why was this",
        "why alert", "explain the evidence", "supports the conclusion",
        "support that conclusion", "basis for",
    )),
    (INCIDENT_SUMMARY, (
        "chuyen gi da xay ra", "chuyen gi xay ra", "co gi xay ra",
        "tom tat", "tong quan", "su co nay la gi", "giai thich su co",
        "noi cho toi biet ve su co", "mo ta su co",
        "what happened", "summarise", "summarize", "summary", "overview",
        "what is this incident", "what's this incident",
        "explain this incident", "tell me about this incident",
        "describe the incident",
    )),
)


def route(question: str) -> str:
    """-> mã ý định, hoặc `OUT_OF_SCOPE_CHAT`. THUẦN, không I/O, không model.

    Yêu cầu hành động và câu lạc đề bị `chat_scope.classify` chặn TRƯỚC: một
    câu vừa xin hành động vừa nghe như câu hỏi ("hãy cách ly rồi tóm tắt cho
    tôi") phải ra ngoài phạm vi, không được rơi vào nhánh tóm tắt.
    """
    kind = classify(question)
    if kind in (ACTION_REQUEST, OUT_OF_SCOPE):
        return OUT_OF_SCOPE_CHAT
    folded = _fold(question)
    if not folded:
        return OUT_OF_SCOPE_CHAT
    for code, phrases in _PATTERNS:
        if any(phrase in folded for phrase in phrases):
            return code
    return OUT_OF_SCOPE_CHAT


def quick_intents() -> tuple[str, ...]:
    """Thứ tự nút bấm nhanh trên giao diện. Cùng nguồn với bộ ý định."""
    return (INCIDENT_SUMMARY, EVIDENCE_EXPLANATION, CERTAINTY,
            RELATED_PROCESS, NEXT_INVESTIGATION_STEP)
