"""Trả lời TẤT ĐỊNH cho những ý định mà dữ liệu đã trả lời trọn vẹn.

Ba trong năm ý định không cần model. Không phải vì model làm hỏng, mà vì nó
không thêm gì: "tiến trình nào liên quan" có đáp án nằm sẵn trong
`confirmed_facts`, và diễn đạt lại nó bằng một lượt suy luận 25 giây là đổi
một câu chắc chắn đúng lấy một câu có thể sai.

Model chỉ được gọi ở nơi văn xuôi THÊM giá trị: tóm tắt sự cố và giải thích
bằng chứng — đúng hai việc mà bản đo phase trước cho thấy model 1,5B làm được.
"""

from __future__ import annotations

from shield.ai.chat_intents import (CERTAINTY, EVIDENCE_EXPLANATION,
                                    INCIDENT_SUMMARY, NEXT_INVESTIGATION_STEP,
                                    RELATED_PROCESS, facts_available, intent_of)

# Số dữ kiện tối đa đưa vào một câu tóm tắt. Bốn là đủ để nói rõ chuyện gì,
# và ít hơn một danh sách dài mà không ai đọc hết.
MAX_SUMMARY_FACTS = 4

# Trạng thái nhận thức -> cách NÓI về mức chắc chắn. Không có mục nào cho
# `CONFIRMED_FACT`: Shield không tự nhận đã xác nhận điều gì trong một câu tóm
# tắt tự động.
_EVIDENCE_WORDING = {
    "SUPPORTED_HYPOTHESIS": "chat.summary.evidence.supported",
    "UNCONFIRMED": "chat.summary.evidence.unconfirmed",
    "INSUFFICIENT_EVIDENCE": "chat.summary.evidence.insufficient",
}

_STATE_KEYS = {
    "CONFIRMED_FACT": "chat.state_word.confirmed",
    "SUPPORTED_HYPOTHESIS": "chat.state_word.supported",
    "UNCONFIRMED": "chat.state_word.unconfirmed",
    "INSUFFICIENT_EVIDENCE": "chat.state_word.insufficient",
}


def _localised(key: str, locale: str) -> str:
    from shield.ui.i18n import STRINGS

    vietnamese, english = STRINGS.get(key, (key, key))
    return english if str(locale).startswith("en") else vietnamese


def _fact_pairs(facts: dict, locale: str, limit: int) -> list[str]:
    """`{khoá: giá trị}` -> ["Nhãn: giá trị"], giá trị in NGUYÊN VĂN.

    Không cắt, không làm tròn, không chuẩn hoá định danh. Đây chính là chỗ model
    đã sai: nó viết `426601:419324` cho `426601:4193241`.
    """
    out = []
    for key, value in list((facts or {}).items())[:limit]:
        label = _localised(f"report.fact.{key}", locale)
        if isinstance(value, (list, tuple)):
            rendered = ", ".join(str(item) for item in value[:4])
        else:
            rendered = str(value)
        out.append(f"{label}: {rendered}"[:160])
    return out


def _limit_texts(report: dict, locale: str) -> list[str]:
    """Giới hạn đã thay tham số. Quên thay thì người đọc thấy `{have}`."""
    out = []
    for item in report.get("limitations", []) or []:
        template = _localised(item.get("key", ""), locale)
        try:
            out.append(template.format(**(item.get("params") or {})))
        except (KeyError, IndexError, ValueError):
            out.append(template)
    return out


def deterministic_answer(code: str, report: dict, locale: str = "vi") -> tuple[str, list]:
    """-> (câu trả lời, danh sách ref). Chuỗi rỗng nghĩa là cần tới model.

    Không có nhánh nào ở đây sinh worker, và không có nhánh nào đọc gì ngoài
    báo cáo tất định đã dựng sẵn.
    """
    intent = intent_of(code)
    if intent is None or intent.model_allowed:
        return "", []

    facts = report.get("confirmed_facts") or {}
    refs = list(report.get("validated_evidence", {}).get("refs", []))

    if code == RELATED_PROCESS:
        if not facts_available(intent, facts):
            return _localised("chat.answer.no_process", locale), []
        identity = str(facts.get("process_identity", ""))
        text = _localised("chat.answer.process", locale).format(identity=identity)
        return text, (refs if intent.attach_refs else [])

    if code == CERTAINTY:
        state = str(report.get("epistemic_state", "UNCONFIRMED"))
        word = _localised(_STATE_KEYS.get(state, _STATE_KEYS["UNCONFIRMED"]), locale)
        # Giới hạn mang THAM SỐ (`{have}`, `{need}`). Quên thay chúng thì người
        # đọc thấy nguyên cái dấu ngoặc — đúng lớp lỗi "khoá dịch thô" đã gặp ở
        # phần báo cáo, chỉ khác chỗ.
        limits = _limit_texts(report, locale)
        text = _localised("chat.answer.certainty", locale).format(state=word)
        if limits:
            text += " " + _localised("chat.answer.certainty_limits", locale).format(
                limits="; ".join(limits[:3]))
        return text, []

    if code == INCIDENT_SUMMARY:
        # Câu tóm tắt dựng từ CHÍNH dữ liệu chuẩn tắc, không qua model.
        #
        # Model 1,5B trượt đúng việc này theo hai cách đo được: nó chép hụt một
        # chữ số của `process_identity` (12/12 lượt, và bộ kiểm phải bỏ cả câu),
        # rồi khi bỏ định danh khỏi ngữ cảnh thì nó gọi một chuỗi thực thi là
        # "một cuộc tấn công mạng" — sai loại sự cố, và bộ kiểm giá trị không
        # bắt được vì đó là một KHẲNG ĐỊNH chứ không phải một con số.
        #
        # Bản dựng ở đây không có cách nào mắc cả hai lỗi đó: tên kịch bản lấy
        # từ registry, định danh in nguyên văn từ dữ liệu.
        scenario = report.get("incident_type", {})
        name = _localised(scenario.get("template_key", "") or "", locale)
        if not name or name.startswith("report.template."):
            name = _localised("chat.summary.unknown_scenario", locale)
        subject = str(report.get("affected_asset", {}).get("subject", "") or "")
        parts = [_localised("chat.summary.observed", locale).format(
            scenario=name, subject=subject or _localised("chat.summary.this_host", locale))]

        pairs = _fact_pairs(facts, locale, MAX_SUMMARY_FACTS)
        if pairs:
            parts.append(_localised("chat.summary.facts", locale).format(
                facts="; ".join(pairs)))

        state = str(report.get("epistemic_state", "UNCONFIRMED"))
        count = int(report.get("validated_evidence", {}).get("count", 0))
        parts.append(_localised(
            _EVIDENCE_WORDING.get(state, _EVIDENCE_WORDING["UNCONFIRMED"]),
            locale).format(count=count))

        limits = _limit_texts(report, locale)
        if limits:
            parts.append(_localised("chat.summary.limitation", locale).format(
                limitation=limits[0]))
        return " ".join(parts), (refs if intent.attach_refs else [])

    if code == EVIDENCE_EXPLANATION:
        count = int(report.get("validated_evidence", {}).get("count", 0))
        if not count:
            return _localised("chat.answer.no_evidence", locale), []
        pairs = []
        for key, value in list(facts.items())[:4]:
            label = _localised(f"report.fact.{key}", locale)
            rendered = ", ".join(str(v) for v in value[:4]) if isinstance(value, list) \
                else str(value)
            pairs.append(f"{label}: {rendered}"[:120])
        text = _localised("chat.answer.evidence", locale).format(
            count=count, facts="; ".join(pairs))
        return text, (refs if intent.attach_refs else [])

    if code == NEXT_INVESTIGATION_STEP:
        codes = list(report.get("recommended_next_steps", {}).get("codes", []))
        if not codes:
            return _localised("chat.answer.no_next_step", locale), []
        # CHỈ tên bước, và chỉ từ danh sách kịch bản đã cho phép. Đây là lời
        # khuyên để người đọc tự làm, không phải một nút bấm — chat không thực
        # hiện hành động nào, và câu chữ ở đây phải nói đúng như vậy.
        steps = "; ".join(_localised(f"report.action.{step}", locale)
                          for step in codes[:3])
        return _localised("chat.answer.next_step", locale).format(steps=steps), []

    return "", []


def needs_model(code: str) -> bool:
    intent = intent_of(code)
    return bool(intent and intent.model_allowed)
