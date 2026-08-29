"""Màn hình hỏi đáp sự cố — dựng nội dung THUẦN, không cần Qt.

Cùng bất biến trung tâm như `report_view`: những gì Shield ĐO ĐƯỢC và những gì
model VIẾT RA đi ra hai chỗ khác nhau, và giao diện không có cách nào nối chúng
lại. Ở đây thêm một bất biến nữa — ref bằng chứng đi kèm câu trả lời do backend
gắn từ dữ liệu đã kiểm, nên một ref hiện trên màn hình luôn mở được.
"""

from __future__ import annotations

# Trạng thái ĐÓNG, dùng lại đúng bộ của phần làm giàu để người đọc chỉ phải học
# một bảng từ vựng.
# `ready` KHÔNG có trong bảng: khi đã có câu trả lời thì dòng trạng thái phải
# im lặng, và một khoá dịch rỗng vừa vô nghĩa vừa là thứ sẽ hiện ra nguyên văn
# nếu có ai đó tra nó — đúng lỗi đã gặp với `report.fact.*`.
STATUS_KEYS = {
    "pending": "chat.state.pending",
    "failed": "chat.state.failed",
    "stale": "chat.state.failed",
    "disabled": "chat.state.disabled",
    "ineligible": "chat.state.ineligible",
}
POLLABLE = frozenset({"pending"})

REJECTION_KEYS = {
    "question_in_flight": "chat.rejected.question_in_flight",
    "session_full": "chat.rejected.session_full",
    "queue_full": "chat.rejected.queue_full",
    "empty_question": "chat.rejected.empty_question",
    "unknown_session": "chat.rejected.unknown_session",
}


def turns(state: dict) -> list[dict]:
    """Hội thoại đã ghép cặp hỏi–đáp, cũ trước.

    Chỉ lấy tin nhắn trợ lý làm mốc: câu hỏi nằm sẵn trong đó, nên không có
    cách nào hiện một câu hỏi mà mất câu trả lời của nó, hay ngược lại.
    """
    out = []
    for message in state.get("messages", []) or []:
        if message.get("role") != "assistant":
            continue
        out.append({
            "question": str(message.get("question", "") or ""),
            "answer": str(message.get("answer", "") or ""),
            "limitations": str(message.get("limitations", "") or ""),
            "refs": [str(ref) for ref in message.get("ref_ids", []) or []],
            "status": str(message.get("status", "") or ""),
            "failure_code": str(message.get("failure_code", "") or ""),
        })
    return out          # thứ tự do backend quyết (turn_index), không sắp lại


def status_line(state: dict, translate) -> str:
    """Một dòng nói tình trạng. Trạng thái lạ rơi về `failed`, không rơi về rỗng."""
    status = str(state.get("status", "") or "")
    if status == "rejected":
        return translate(REJECTION_KEYS.get(str(state.get("reason", "")),
                                            "chat.state.failed"))
    if status in ("ready", ""):
        pending = any(turn["status"] == "pending" for turn in turns(state))
        return translate("chat.state.pending") if pending else ""
    return translate(STATUS_KEYS.get(status, "chat.state.failed"))


def should_poll(state: dict) -> bool:
    """Chỉ hỏi lại khi thật sự có câu đang chờ."""
    if str(state.get("status", "")) in POLLABLE:
        return True
    return any(turn["status"] in POLLABLE for turn in turns(state))


def can_ask(state: dict) -> bool:
    """Ô nhập có dùng được không.

    Tắt khi AI tắt, khi kịch bản không đủ điều kiện, và khi đang có một câu
    chờ trả lời — trần một câu một lúc là trần thật, nên giao diện phải nói ra
    điều đó thay vì để người dùng gõ rồi bị từ chối.
    """
    if str(state.get("status", "")) in ("disabled", "ineligible"):
        return False
    if not state.get("session_id"):
        return False
    return not any(turn["status"] in POLLABLE for turn in turns(state))


def evidence_refs(state: dict) -> list[str]:
    """Mọi ref xuất hiện trong hội thoại, không trùng, giữ thứ tự."""
    seen: list[str] = []
    for turn in turns(state):
        for ref in turn["refs"]:
            if ref not in seen:
                seen.append(ref)
    return seen
