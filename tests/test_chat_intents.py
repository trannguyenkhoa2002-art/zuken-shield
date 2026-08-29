"""Hỏi đáp theo Ý ĐỊNH ĐÓNG.

Chat mở đã trượt vì đúng một lý do, và đó là lý do đã trượt một lần trước ở
tầng kịch bản: model 1,5B điền khuôn tốt, tự chọn phải nói gì thì tệ. Nên ở
đây model không bao giờ được hỏi "câu này hỏi gì", và ba trong năm ý định
không gọi model chút nào.
"""

from __future__ import annotations

import json
import pathlib
from collections import Counter

import pytest

from shield.agent.store import Store
from shield.ai.chat_answer import deterministic_answer, needs_model
from shield.ai.chat_intents import (CERTAINTY, CHAT_INTENTS, DETERMINISTIC,
                                    EVIDENCE_EXPLANATION, INCIDENT_SUMMARY,
                                    MODEL_BACKED, NEXT_INVESTIGATION_STEP,
                                    OUT_OF_SCOPE_CHAT, RELATED_PROCESS, intent_of)
from shield.ai.chat_router import quick_intents, route
from shield.common.models import Alert
from shield.ai.worker.prompt import intent_task
from shield.ui.i18n import STRINGS

CORPUS = json.loads(
    pathlib.Path("shield/evals/datasets/chat-intent-corpus.json").read_text(
        encoding="utf-8"))
NOW = 1000.0


def _incident(tmp_path, rule_id="LOCAL_SSH_BRUTEFORCE",
              correlation_id="ACCUMULATED_AUTH_FAILURES", evidence=None):
    store = Store(tmp_path / "s.db")
    store.insert_alert(Alert(NOW, rule_id, "warning", "t", "d", "192.168.1.77",
                             evidence=evidence or {"src_ip": "192.168.1.77",
                                                   "fail_count": 37},
                             playbook=["snapshot_state"]))
    incident_id = store.open_or_update_incident(
        correlation_id=correlation_id, subject="192.168.1.77", title="t",
        severity="warning", risk_score=61, evidence_strength=0.6,
        recommended_action="snapshot_state",
        contributing=[{"rule_id": rule_id, "ts": NOW, "severity": "warning",
                       "detail": ""}])["incident_id"]
    from shield.report.incident import build

    return store, build(store, incident_id)


# --- §1 ánh xạ ý định phải TẤT ĐỊNH và 100% ----------------------------


def test_the_corpus_is_big_enough_and_not_padded():
    samples = CORPUS["samples"]
    assert len(samples) >= 100, len(samples)
    questions = [s["question"] for s in samples]
    assert len(set(questions)) == len(questions), "có câu trùng để lấy số lượng"
    per = Counter(s["intent"] for s in samples)
    for code in CHAT_INTENTS:
        assert per[code] >= 15, f"{code} chỉ có {per[code]} mẫu"
    assert per[OUT_OF_SCOPE_CHAT] >= 15
    languages = Counter(s["lang"] for s in samples)
    assert languages["vi"] >= 40 and languages["en"] >= 40, languages


@pytest.mark.parametrize("sample", CORPUS["samples"],
                         ids=lambda s: s["question"][:40])
def test_every_corpus_question_maps_to_its_intent(sample):
    """§8: cổng ánh xạ là 100%, không phải 95%."""
    assert route(sample["question"]) == sample["intent"]


def test_intent_mapping_never_asks_the_model():
    """Bài học đã trả giá hai lần: model không phân loại."""
    import inspect

    from shield.ai import chat_router

    source = inspect.getsource(chat_router)
    for forbidden in ("LocalModelAnalyst", "WorkerRequest", "generate", "llama"):
        assert forbidden not in source, forbidden


def test_the_quick_buttons_cover_every_answerable_intent():
    assert set(quick_intents()) == set(CHAT_INTENTS)
    for code in quick_intents():
        assert f"chat.question.{code}" in STRINGS
        assert f"chat.intent.{code}" in STRINGS
        # Câu chuẩn của nút phải tự ánh xạ về chính ý định đó.
        assert route(STRINGS[f"chat.question.{code}"][0]) == code
        assert route(STRINGS[f"chat.question.{code}"][1]) == code


# --- §3 ý định nào KHÔNG cần model --------------------------------------


def test_a_deterministic_intent_answers_from_the_report(tmp_path):
    store, report = _incident(tmp_path)
    for code in DETERMINISTIC:
        answer, _refs = deterministic_answer(code, report, "vi")
        assert answer.strip(), code
        assert "{" not in answer, f"{code}: còn placeholder chưa thay"


def test_related_process_says_so_when_there_is_no_process(tmp_path):
    """§2: thiếu dữ kiện bắt buộc -> câu trả lời tất định, không phải suy đoán."""
    store, report = _incident(tmp_path)
    answer, refs = deterministic_answer(RELATED_PROCESS, report, "vi")
    assert answer == STRINGS["chat.answer.no_process"][0]
    assert refs == []


def test_related_process_reports_the_real_identity(tmp_path):
    store, report = _incident(
        tmp_path, rule_id="BEHAVIOR_EXEC_WRITE_CONNECT", correlation_id="K",
        evidence={"process_identity": "4242:99", "sequence": ["process_exec"]})
    answer, _refs = deterministic_answer(RELATED_PROCESS, report, "vi")
    assert "4242:99" in answer


def test_next_step_advice_never_offers_to_act(tmp_path):
    """§2: lời khuyên, KHÔNG phải nút bấm."""
    store, report = _incident(tmp_path)
    answer, _ = deterministic_answer(NEXT_INVESTIGATION_STEP, report, "vi")
    assert "không tự thực hiện" in answer
    english, _ = deterministic_answer(NEXT_INVESTIGATION_STEP, report, "en")
    assert "does not carry" in english


def test_certainty_never_claims_confirmation(tmp_path):
    from shield.report.template import asserts_confirmation

    store, report = _incident(tmp_path)
    for locale in ("vi", "en"):
        answer, _ = deterministic_answer(CERTAINTY, report, locale)
        assert not asserts_confirmation(answer), answer


def test_a_model_backed_intent_returns_nothing_deterministic(tmp_path):
    store, report = _incident(tmp_path)
    for code in MODEL_BACKED:
        assert deterministic_answer(code, report, "vi") == ("", [])


def test_evidence_explanation_answers_without_the_model(tmp_path):
    store, report = _incident(tmp_path)
    answer, _refs = deterministic_answer(EVIDENCE_EXPLANATION, report, "vi")
    assert answer.strip() and "{" not in answer
    assert needs_model(EVIDENCE_EXPLANATION) is False


# --- §4 registry --------------------------------------------------------


def test_the_registry_is_closed_and_self_consistent():
    for code, intent in CHAT_INTENTS.items():
        assert intent.code == code
        assert 0 < intent.max_answer_chars <= 600
        assert intent.fallback_key in STRINGS, intent.fallback_key
        assert "CONFIRMED_FACT" not in intent.allowed_states, code
    assert OUT_OF_SCOPE_CHAT not in CHAT_INTENTS, "ngoài phạm vi không phải một ý định trả lời"


def test_there_is_only_one_scenario_registry():
    """§4: không dựng registry kịch bản thứ hai."""
    import inspect

    from shield.ai import chat_intents

    source = inspect.getsource(chat_intents)
    assert "SCENARIOS" not in source and "rule_id" not in source


# --- §5 ngoài phạm vi ---------------------------------------------------


@pytest.mark.parametrize("question", [
    "Isolate host now", "Block this IP", "Run a scan", "Write Python",
    "What's the weather?", "What else can you do?",
    "Hãy cách ly máy này ngay", "Giá bitcoin hôm nay?",
])
def test_out_of_scope_questions_refuse_deterministically(question):
    assert route(question) == OUT_OF_SCOPE_CHAT


def test_the_refusal_names_the_limit():
    for text in STRINGS["chat.answer.out_of_scope_chat"]:
        assert "limited" in text.lower() or "giới hạn" in text.lower()


# --- §9 bộ chấm lặp -----------------------------------------------------


def test_the_repetition_scorer_catches_the_observed_loop():
    from shield.evals.chat_quality import is_repetitive

    observed = ("Shield đã xác định một sự cố an ninh đã được phân tích trước đó. "
                "Nó đã xác định rằng Shield đã phân tích một sự cố an ninh đã được "
                "phân tích trước đó. Nó đã xác định rằng Shield đã phân tích một "
                "sự cố an ninh đã được phân tích trước đó.")
    assert is_repetitive(observed) is True
    good = ("Shield ghi nhận một tiến trình thực thi rồi ghi nhiều tệp và sau đó "
            "mở một kết nối ra ngoài. Ba mốc này liên tiếp trong cùng một cây "
            "tiến trình.")
    assert is_repetitive(good) is False


def test_the_repeat_penalty_is_off_by_default_and_bounded():
    """§9: không thêm ngẫu nhiên để giấu lặp — nhiệt độ vẫn 0."""
    from shield.ai.model_config import ModelConfig

    assert ModelConfig().repeat_penalty == 1.0
    assert ModelConfig().temperature == 0.0
    assert ModelConfig.parse({"model_path": "/x", "repeat_penalty": 99}
                             ).repeat_penalty <= 1.5


# --- §2 prompt theo ý định ---------------------------------------------


def test_the_model_prompt_mechanism_is_dormant_not_deleted():
    """§8: giữ cơ chế cho bản sau, nhưng KHÔNG để lại nhiệm vụ nào đang sống.

    Một prompt còn nằm đó cho một ý định đã tất định là cái bẫy đúng nghĩa:
    người đọc sau sẽ tin rằng nhánh model vẫn chạy.
    """
    from shield.ai.worker.prompt import _INTENT_TASKS, build_intent_prompt

    assert _INTENT_TASKS == {}, "còn nhiệm vụ model cho một ý định đã tất định"
    for code in CHAT_INTENTS:
        assert intent_task(code, "vi") == "", code
    assert callable(build_intent_prompt), "đừng xoá cơ chế, chỉ ngủ đông"


def test_the_intent_prompt_refuses_an_unknown_intent():
    from shield.ai.worker.prompt import build_intent_prompt

    with pytest.raises(ValueError):
        build_intent_prompt({}, "KHONG_TON_TAI")


# --------------------------------------------------------------------------
# Giao diện: MỘT đường định tuyến, và không tự quyết gì


UI_SRC = pathlib.Path("shield/ui/__main__.py").read_text(encoding="utf-8")
VIEW_SRC = pathlib.Path("shield/ui/chat_view.py").read_text(encoding="utf-8")


def test_the_ui_never_decides_intent_or_eligibility():
    """§2: backend là nơi có thẩm quyền. Giao diện chỉ vẽ thứ nó nhận được."""
    for source in (UI_SRC, VIEW_SRC):
        for forbidden in ("CHAT_INTENTS", "explanation_enabled", "MODEL_BACKED",
                          "deterministic_answer", "epistemic_state",
                          "allowed_values", "route("):
            assert forbidden not in source, forbidden
    # Nút bấm chỉ được dùng registry để lấy THỨ TỰ và NHÃN, không để quyết định.
    assert "chat_router.quick_intents()" in UI_SRC


def test_both_entry_paths_share_one_router():
    """Nút bấm gửi CÂU HỎI, không gửi mã ý định — nên chỉ có một bộ ánh xạ."""
    block = UI_SRC[UI_SRC.index("def _ask_intent"):]
    block = block[:block.index("\n    def ", 10)]
    assert "chat.question." in block and "_send_chat()" in block
    assert '"cmd": "chat_send"' not in block, "nút bấm đi đường riêng"


@pytest.mark.parametrize("status,key", [
    ("disabled", "chat.state.disabled"),
    ("ineligible", "chat.state.ineligible"),
    ("failed", "chat.state.failed"),
    ("stale", "chat.state.failed"),
])
def test_every_backend_state_has_a_translated_line(status, key):
    from shield.ui import chat_view

    state = {"status": status, "session_id": "", "messages": []}
    assert chat_view.status_line(state, lambda k: k) == key
    assert STRINGS[key][0].strip() and STRINGS[key][1].strip()


@pytest.mark.parametrize("reason", ["question_in_flight", "session_full",
                                    "queue_full", "empty_question",
                                    "unknown_session"])
def test_every_rejection_reason_has_a_translated_line(reason):
    from shield.ui import chat_view

    line = chat_view.status_line({"status": "rejected", "reason": reason},
                                 lambda k: k)
    assert line in STRINGS, line
    assert STRINGS[line][0].strip() and STRINGS[line][1].strip()


def test_a_rejection_does_not_wipe_the_conversation():
    """Phản hồi từ chối không kèm `messages`; gán đè sẽ xoá trắng lịch sử."""
    block = UI_SRC[UI_SRC.index("def on_chat_state"):]
    block = block[:block.index("\n    def ", 10)]
    assert '"messages" in data' in block, "gán đè state không kiểm messages"


def test_the_ui_does_not_parse_refs_out_of_prose():
    """§4: ref do backend gắn. Giao diện chỉ đọc `ref_ids`."""
    assert "ref_ids" in VIEW_SRC
    for forbidden in ("re.findall", "re.search", "ev:", "event:"):
        assert forbidden not in VIEW_SRC, forbidden


def test_quick_action_labels_exist_in_both_languages():
    from shield.ai.chat_router import quick_intents

    for code in quick_intents():
        for key in (f"chat.intent.{code}", f"chat.question.{code}"):
            vietnamese, english = STRINGS[key]
            assert vietnamese.strip() and english.strip(), key
            assert not vietnamese.startswith("chat."), key


def test_the_limited_notice_sets_expectations():
    for text in STRINGS["chat.limited_notice"]:
        assert "limited" in text.lower() or "giới hạn" in text.lower()


# --------------------------------------------------------------------------
# 3.0.0a2: cả năm ý định TẤT ĐỊNH


def test_no_intent_spawns_a_model_in_this_release():
    """§8: hạ tầng còn đó KHÔNG có nghĩa là có thứ gì đang chạy."""
    assert MODEL_BACKED == frozenset(), MODEL_BACKED
    assert DETERMINISTIC == set(CHAT_INTENTS)
    for code in CHAT_INTENTS:
        assert needs_model(code) is False, code


def test_every_intent_answers_without_a_model(tmp_path):
    store, report = _incident(tmp_path)
    for code in CHAT_INTENTS:
        answer, _refs = deterministic_answer(code, report, "vi")
        assert answer.strip(), code
        assert "{" not in answer, f"{code}: còn placeholder"


def test_the_summary_renders_the_identifier_verbatim(tmp_path):
    """§3: model chép `426601:4193241` thành `426601:419324`. Bản dựng thì không."""
    store, report = _incident(
        tmp_path, rule_id="BEHAVIOR_EXEC_WRITE_CONNECT", correlation_id="K",
        evidence={"process_identity": "426601:4193241",
                  "sequence": ["process_exec", "socket_connect"]})
    for locale in ("vi", "en"):
        answer, _refs = deterministic_answer(INCIDENT_SUMMARY, report, locale)
        assert "426601:4193241" in answer, answer
        assert "426601:419324 " not in answer, "định danh bị cắt"


def test_the_summary_never_uses_unsupported_words(tmp_path):
    """§2: không "bị chiếm quyền", không "tấn công", không "mã độc"…

    Model từng gọi một chuỗi thực thi là "một cuộc tấn công mạng". Bản dựng lấy
    tên loại sự cố từ registry, nên nó không có chỗ để nói thêm.
    """
    forbidden_vi = ("bị chiếm quyền", "tấn công", "mã độc", "trụ lại",
                    "lan ngang", "rút dữ liệu", "xâm nhập")
    forbidden_en = ("compromised", "attack", "malware", "persistence",
                    "lateral movement", "exfiltration", "breach")
    for rule, corr, evidence in [
        ("BEHAVIOR_EXEC_WRITE_CONNECT", "K",
         {"process_identity": "1:2", "sequence": ["process_exec"]}),
        ("LOCAL_SSH_BRUTEFORCE", "ACCUMULATED_AUTH_FAILURES", None),
    ]:
        store, report = _incident(tmp_path / rule, rule_id=rule,
                                  correlation_id=corr, evidence=evidence)
        vietnamese, _ = deterministic_answer(INCIDENT_SUMMARY, report, "vi")
        english, _ = deterministic_answer(INCIDENT_SUMMARY, report, "en")
        for word in forbidden_vi:
            assert word not in vietnamese.lower(), (rule, word, vietnamese)
        for word in forbidden_en:
            assert word not in english.lower(), (rule, word, english)


def test_the_summary_states_what_is_uncertain(tmp_path):
    store, report = _incident(tmp_path)
    for locale, marker in (("vi", "chưa"), ("en", "not")):
        answer, _ = deterministic_answer(INCIDENT_SUMMARY, report, locale)
        assert marker in answer.lower(), answer


def test_the_summary_attaches_validated_refs_only(tmp_path):
    store, report = _incident(tmp_path)
    _answer, refs = deterministic_answer(INCIDENT_SUMMARY, report, "vi")
    for ref in refs:
        assert ref in report["validated_evidence"]["refs"]


# --- §7 cổng: hỏi đáp tất định KHÔNG cần đồng ý chạy AI ------------------


def _send(store, incident_id, question):
    from shield.agent.__main__ import chat_send

    return chat_send(store, incident_id, question)


def _live_store(tmp_path):
    from shield.agent.__main__ import EXPLANATION_OPT_IN_KEY

    store = Store(tmp_path / "s.db")
    store.insert_alert(Alert(NOW, "BEHAVIOR_EXEC_WRITE_CONNECT", "warning", "t", "d",
                             "victus",
                             evidence={"process_identity": "426601:4193241",
                                       "sequence": ["process_exec"]},
                             playbook=["snapshot_state"]))
    incident_id = store.open_or_update_incident(
        correlation_id="K", subject="victus", title="t", severity="warning",
        risk_score=61, evidence_strength=0.6, recommended_action="snapshot_state",
        contributing=[{"rule_id": "BEHAVIOR_EXEC_WRITE_CONNECT", "ts": NOW,
                       "severity": "warning", "detail": ""}])["incident_id"]
    store.set_baseline(EXPLANATION_OPT_IN_KEY, "0")     # ĐỒNG Ý AI: TẮT
    return store, incident_id


@pytest.mark.parametrize("provider,kill", [
    ("disabled", None), ("disabled", "1"), ("local_model", "1"),
])
def test_guided_qa_works_without_any_ai_consent(tmp_path, monkeypatch, provider, kill):
    """§7: công tắc AI là của việc chạy model, không phải của phân tích Shield.

    Máy vừa nâng cấp gói xong — `llama-cpp-python` đã bị `venv --clear` xoá —
    vẫn phải hỏi đáp được đầy đủ.
    """
    monkeypatch.setenv("SHIELD_AI_PROVIDER", provider)
    if kill:
        monkeypatch.setenv("SHIELD_AI_KILL_SWITCH", kill)
    else:
        monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store, incident_id = _live_store(tmp_path)
    for code in CHAT_INTENTS:
        result = _send(store, incident_id, STRINGS[f"chat.question.{code}"][0])
        assert result["status"] == "ready", (code, result["status"])
        assert result["intent"] == code
        assert result["message"]["answer"].strip(), code
    from shield.ai.chat import ChatStore

    counts = ChatStore(store.conn).counts()
    assert "pending" not in counts and "running" not in counts, counts


def test_guided_qa_needs_no_llama_import(tmp_path, monkeypatch):
    """§13: không có `llama_cpp` thì hỏi đáp vẫn chạy."""
    import builtins

    real = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "llama_cpp" or name.startswith("llama_cpp."):
            raise ImportError("No module named 'llama_cpp'")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store, incident_id = _live_store(tmp_path)
    result = _send(store, incident_id, "Tóm tắt sự cố này.")
    assert result["status"] == "ready"
    assert "426601:4193241" in result["message"]["answer"]


def test_the_ui_does_not_call_the_feature_ai():
    """§6/§12: không câu nào do model viết, nên đừng gọi nó là AI."""
    for text in STRINGS["chat.limited_notice"]:
        assert "ai" not in text.lower().split("—")[0].replace("hỏi đáp", "")
    assert STRINGS["chat.ai"] == ("Shield", "Shield")
    for text in STRINGS["chat.subordinate"]:
        assert "model" in text.lower()


def test_the_answer_language_follows_the_caller_not_the_agent(tmp_path, monkeypatch):
    """Câu trả lời hỏi đáp được DỰNG THÀNH CHỮ ở phía agent.

    Khác báo cáo, thứ trả về khoá để giao diện tự dịch. Nên nếu ngôn ngữ không
    được truyền xuống, người dùng giao diện tiếng Anh nhận về câu trả lời tiếng
    Việt — và mặc định `locale="vi"` khiến lỗi đó im lặng.
    """
    from shield.agent.__main__ import chat_send

    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store, incident_id = _live_store(tmp_path)
    vietnamese = chat_send(store, incident_id, "Tóm tắt sự cố này.", "vi")
    english = chat_send(store, incident_id, "Summarise this incident.", "en")
    assert "Shield ghi nhận" in vietnamese["message"]["answer"]
    assert "Shield observed" in english["message"]["answer"]
    # Định danh giữ nguyên ở CẢ HAI ngôn ngữ.
    for result in (vietnamese, english):
        assert "426601:4193241" in result["message"]["answer"]


def test_the_ui_sends_its_language_with_every_chat_command():
    """Ba lệnh chat đều phải mang ngôn ngữ, không chỉ lệnh gửi câu hỏi."""
    for command in ("chat_send", "chat_history", "chat_open"):
        index = UI_SRC.index(f'"cmd": "{command}"')
        block = UI_SRC[index:index + 320]
        assert "current_lang()" in block, command
