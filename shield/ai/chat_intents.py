"""Bộ Ý ĐỊNH ĐÓNG cho hỏi đáp sự cố.

Chat v0 mở là một thất bại đã đo được: cùng một model viết tốt phần giải thích
theo khuôn lại lặp câu và trả lời hai câu hỏi khác nhau y hệt nhau khi được hỏi
tự do. Bài học giống hệt lần bỏ phân loại kịch bản bằng model — model làm tốt
việc ĐIỀN vào một khuôn đã định, và làm tệ việc TỰ CHỌN phải nói gì.

Nên ở đây người dùng vẫn gõ tiếng Việt hay tiếng Anh tự nhiên, nhưng backend
ánh xạ câu đó về một trong năm ý định dưới đây bằng luật TẤT ĐỊNH. Model không
bao giờ được hỏi "câu này hỏi gì" — đó chính là phép thử đã trượt.

Mỗi ý định khai rõ: cần dữ kiện gì, có được gọi model không, dài tối đa bao
nhiêu, có gắn bằng chứng không, và câu trả lời tất định thay thế là gì.
"""

from __future__ import annotations

from dataclasses import dataclass, field

INCIDENT_SUMMARY = "INCIDENT_SUMMARY"
EVIDENCE_EXPLANATION = "EVIDENCE_EXPLANATION"
CERTAINTY = "CERTAINTY"
RELATED_PROCESS = "RELATED_PROCESS"
NEXT_INVESTIGATION_STEP = "NEXT_INVESTIGATION_STEP"
OUT_OF_SCOPE_CHAT = "OUT_OF_SCOPE_CHAT"


@dataclass(frozen=True)
class Intent:
    """Một ý định. `model_allowed=False` nghĩa là KHÔNG BAO GIỜ sinh worker."""

    code: str
    required_fact_keys: tuple[str, ...] = ()
    # Có gọi model không. Chỉ bật ở nơi văn xuôi THÊM giá trị so với bản tất
    # định — xem `deterministic_answer`. Một lượt suy luận 25 giây để diễn đạt
    # lại một câu Shield đã biết là 25 giây đổi lấy rủi ro bịa đặt.
    model_allowed: bool = False
    max_answer_chars: int = 400
    attach_refs: bool = False
    # Trạng thái nhận thức mà ý định này có nghĩa. `CONFIRMED_FACT` không nằm
    # trong danh sách nào: Shield không tự nhận đã xác nhận điều gì.
    allowed_states: tuple[str, ...] = ("UNCONFIRMED", "SUPPORTED_HYPOTHESIS",
                                       "INSUFFICIENT_EVIDENCE")
    fallback_key: str = "chat.answer.no_data"


CHAT_INTENTS: dict[str, Intent] = {
    # Hai ý định model được phép viết: cả hai đều là TÓM TẮT dữ liệu đã có,
    # đúng việc model 1,5B làm được — đã đo ở phase trước.
    # TẤT ĐỊNH từ 3.0.0a2. Model 1,5B trượt việc này theo hai cách đo được: chép
    # hụt một chữ số của định danh tiến trình (12/12 lượt, bộ kiểm phải bỏ cả
    # câu), và khi bỏ định danh khỏi ngữ cảnh thì gọi một chuỗi thực thi là
    # "một cuộc tấn công mạng" — sai loại sự cố, mà bộ kiểm giá trị không bắt
    # được vì đó là khẳng định chứ không phải con số.
    INCIDENT_SUMMARY: Intent(
        code=INCIDENT_SUMMARY, model_allowed=False, max_answer_chars=600,
        attach_refs=True, fallback_key="chat.answer.no_summary"),
    # TẮT model cho ý định này, đo được chứ không phỏng đoán: bằng tiếng Việt
    # nó lặp câu 100% và bị bộ kiểm bỏ 100%. Tiếng Anh thì đạt — nhưng ngôn ngữ
    # mặc định của Shield là tiếng Việt, và một tính năng chỉ chạy được ở ngôn
    # ngữ phụ thì không phải một tính năng.
    #
    # Bản tất định trả lời trọn vẹn: đếm bằng chứng đã kiểm, liệt kê dữ kiện
    # chuẩn tắc, gắn ref. Không có gì để model thêm vào ngoài rủi ro.
    EVIDENCE_EXPLANATION: Intent(
        code=EVIDENCE_EXPLANATION, model_allowed=False,
        max_answer_chars=400, attach_refs=True,
        fallback_key="chat.answer.no_evidence"),
    # Ba ý định TẤT ĐỊNH. Dữ liệu đã trả lời trọn vẹn; thêm model chỉ thêm
    # đường để sai.
    CERTAINTY: Intent(
        code=CERTAINTY, model_allowed=False, attach_refs=False,
        fallback_key="chat.answer.certainty"),
    RELATED_PROCESS: Intent(
        code=RELATED_PROCESS, required_fact_keys=("process_identity",),
        model_allowed=False, attach_refs=True,
        fallback_key="chat.answer.no_process"),
    NEXT_INVESTIGATION_STEP: Intent(
        code=NEXT_INVESTIGATION_STEP, model_allowed=False, attach_refs=False,
        fallback_key="chat.answer.no_next_step"),
}

# 3.0.0a2: RỖNG. Không ý định nào gọi model.
#
# Hạ tầng model vẫn nằm nguyên trong cây — worker cách ly, scope cgroup, runner
# dùng chung, `clean_prose`, bảo vệ dấu vân bằng chứng — và `Intent.model_allowed`
# vẫn là công tắc thật. Một bản sau với model đủ tốt chỉ cần bật lại một cờ và
# viết lại prompt cho ý định đó; không phải dựng lại đường ống.
#
# Cho tới lúc đó, tập rỗng này là thứ giữ cho "hạ tầng còn đó" không bị hiểu
# nhầm thành "có thứ gì đó đang chạy".
MODEL_BACKED = frozenset(code for code, intent in CHAT_INTENTS.items()
                         if intent.model_allowed)
DETERMINISTIC = frozenset(CHAT_INTENTS) - MODEL_BACKED


def intent_of(code: str) -> Intent | None:
    return CHAT_INTENTS.get(str(code or ""))


def facts_available(intent: Intent, facts: dict) -> bool:
    """Đủ dữ kiện chuẩn tắc cho ý định này chưa."""
    return all(str(key) in (facts or {}) and (facts or {}).get(key) not in (None, "", [])
               for key in intent.required_fact_keys)
