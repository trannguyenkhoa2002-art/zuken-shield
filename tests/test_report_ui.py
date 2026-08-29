"""Màn hình báo cáo sự cố — dựng nội dung THUẦN, không cần Qt.

Bất biến trung tâm: dữ liệu Shield đo được và văn xuôi model đi ra HAI danh
sách riêng, và giao diện không có cách nào nối chúng lại. Trộn chúng là cách
nhanh nhất để một suy đoán được đọc như một sự thật — đúng thứ mọi lớp phía
dưới đã bỏ công để tránh.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.ai import enrichment as E
from shield.ai.enrichment import EnrichmentStore
from shield.common.models import Alert
from shield.ui import report_view
from shield.ui.i18n import STRINGS

NOW = 1000.0
UI_SRC = pathlib.Path("shield/ui/__main__.py").read_text(encoding="utf-8")


def _t(key):
    return STRINGS[key][1] if key in STRINGS else key


def _fmt(value):
    return str(value or "—")


def _report(**kw):
    base = {
        "incident_type": {"scenario_code": "SSH_BRUTE_FORCE",
                          "family": "AUTHENTICATION_ATTACK", "rule_id": "R",
                          "template_key": "report.template.ssh_brute_force"},
        "severity": {"level": "warning", "risk_score": 61, "evidence_strength": 0.6},
        "time_window": {"first_seen": 1.0, "last_seen": 2.0},
        "affected_asset": {"subject": "192.168.1.77"},
        "confirmed_facts": {"src_ip": "192.168.1.77", "fail_count": 37},
        "missing_required_facts": [],
        "validated_evidence": {"refs": ["event:aaa"], "count": 1},
        "supporting_detections": [{"rule_id": "R2", "scenario_code": "X",
                                   "severity": "info", "ts": 1.0}],
        "recommended_next_steps": {"codes": ["snapshot_state"]},
        "limitations": [],
        "analysis": {"prose": "Có thể là dò mật khẩu.",
                     "hypothesis_rationale": "Nhiều lần sai liên tiếp."},
        "why_this_matters": {"prose": "Đáng xem."},
    }
    base.update(kw)
    return base


# --------------------------------------------------------------------------
# §2 báo cáo tất định hiện trước, đủ mục


def test_the_deterministic_report_shows_every_agreed_section():
    rows = report_view.deterministic_rows(_report(), _t, _fmt)
    sections = {section for _k, _v, section in rows}
    for required in ("incident_type", "severity", "time_window", "affected_asset",
                     "confirmed_facts", "validated_evidence",
                     "supporting_detections", "recommended_next_steps"):
        assert required in sections, required


def test_the_section_order_is_fixed():
    """Người trực đọc báo cáo thứ hai mươi lúc 3 giờ sáng phải biết "bước tiếp
    theo" nằm ở đâu mà không đọc lại từ đầu."""
    assert report_view.SECTION_ORDER[0] == "incident_type"
    assert report_view.SECTION_ORDER[-1] == "limitations"
    rows = report_view.deterministic_rows(_report(), _t, _fmt)
    seen = [s for _k, _v, s in rows]
    order = [s for s in report_view.SECTION_ORDER if s in seen]
    positions = [seen.index(s) for s in order]
    assert positions == sorted(positions), "thứ tự mục bị đảo"


def test_an_empty_report_says_so_instead_of_rendering_nothing():
    assert report_view.deterministic_rows({}, _t, _fmt) == [("report.empty", "",
                                                             "incident_type")]


def test_missing_facts_are_shown_not_hidden():
    rows = report_view.deterministic_rows(
        _report(confirmed_facts={}, missing_required_facts=["fail_count"]), _t, _fmt)
    labels = [k for k, _v, _s in rows]
    assert "report.no_facts" in labels and "report.missing_fact" in labels


# --------------------------------------------------------------------------
# §8 nhãn: dữ liệu Shield KHÁC văn xuôi model


def test_ai_prose_never_appears_in_the_deterministic_rows():
    """Hai danh sách riêng, và không có đường nào nối chúng."""
    rows = report_view.deterministic_rows(_report(), _t, _fmt)
    blob = " ".join(f"{k} {v}" for k, v, _s in rows)
    assert "dò mật khẩu" not in blob
    assert "Đáng xem" not in blob


def test_ai_rows_appear_only_when_ready():
    report = _report()
    for status in ("disabled", "ineligible", "pending", "failed", "deferred"):
        assert report_view.ai_rows(report, {"status": status}, _t) == [], status
    ready = report_view.ai_rows(report, {"status": "ready"}, _t)
    assert [k for k, _v in ready] == ["report.ai.analysis", "report.ai.rationale",
                                      "report.ai.matters"]


def test_empty_slots_are_not_rendered_as_blank_rows():
    report = _report(analysis={"prose": "", "hypothesis_rationale": ""},
                     why_this_matters={"prose": ""})
    assert report_view.ai_rows(report, {"status": "ready"}, _t) == []


def test_the_ai_block_declares_itself_subordinate():
    vietnamese, english = STRINGS["report.ai.subordinate"]
    assert "KHÔNG phải dữ liệu Shield" in vietnamese
    assert "NOT" in english and "complete without it" in english


def test_ai_prose_is_never_labelled_confirmed():
    for key in ("report.ai.title", "report.ai.analysis", "report.ai.rationale",
                "report.ai.matters", "report.ai.subordinate"):
        for text in STRINGS[key]:
            lowered = text.lower()
            for forbidden in ("confirmed", "verified", "ground truth", "đã xác nhận"):
                assert forbidden not in lowered, f"{key}: {text}"


def test_the_ui_renders_ai_prose_in_a_separate_block():
    assert "report_view.ai_rows" in UI_SRC
    assert "report.ai.subordinate" in UI_SRC
    # Khối AI vẽ SAU khối tất định.
    assert UI_SRC.index("report.deterministic_title") < UI_SRC.index("report.ai.title")


# --------------------------------------------------------------------------
# §3 trạng thái


@pytest.mark.parametrize("status", sorted(E.CLIENT_STATUSES))
def test_every_client_status_has_a_translated_line(status):
    key = report_view.STATUS_KEYS[status]
    assert key in STRINGS
    vietnamese, english = STRINGS[key]
    assert vietnamese.strip() and english.strip() and vietnamese != english


def test_an_unknown_status_never_leaks_a_raw_string():
    """Người dùng không đọc mã lỗi của ta."""
    line = report_view.status_line({"status": "khong_biet_la_gi"}, _t)
    assert line == _t("report.ai.state.deferred")
    assert "khong_biet" not in line


def test_failure_states_are_calm_not_alarming():
    for key in ("report.ai.state.failed", "report.ai.state.deferred"):
        for text in STRINGS[key]:
            assert "unaffected" in text or "không bị ảnh hưởng" in text


def test_the_pending_line_says_the_report_is_already_complete():
    for text in STRINGS["report.ai.state.pending"]:
        assert "already complete" in text or "đã đầy đủ" in text


# --------------------------------------------------------------------------
# §5 hỏi lại CÓ TRẦN


@pytest.mark.parametrize("status,expected", [
    ("pending", True), ("ready", False), ("failed", False),
    ("deferred", False), ("disabled", False), ("ineligible", False),
])
def test_polling_stops_on_any_final_state(status, expected):
    assert report_view.should_poll({"status": status}) is expected


def test_polling_is_bounded_in_the_ui():
    """Một vòng hỏi không có trần là một vòng chạy mãi sau khi người dùng đã
    bỏ đi."""
    assert re.search(r"REPORT_POLL_MAX\s*=\s*\d+", UI_SRC)
    assert re.search(r"REPORT_POLL_MS\s*=\s*\d+", UI_SRC)
    assert "self._report_polls >= REPORT_POLL_MAX" in UI_SRC
    assert "not self.isVisible()" in UI_SRC, "phải dừng khi tab không còn hiện"
    assert "self._poll_timer.stop()" in UI_SRC


def test_polling_reuses_the_existing_command():
    """Không kênh mới, không suy luận mới."""
    poll = UI_SRC[UI_SRC.index("def _poll_report"):]
    poll = poll[:poll.index("\n    def ", 10)]
    assert '"cmd": "investigate_incident"' in poll
    assert "enrich" not in poll.replace("ai_enrichment", "")


# --------------------------------------------------------------------------
# §7 điều hướng bằng chứng dùng lại đường đã có


def test_evidence_refs_are_exposed_for_the_existing_viewer():
    assert report_view.evidence_refs(_report()) == ["event:aaa"]
    assert report_view.evidence_refs({}) == []


def test_the_ui_reuses_the_existing_evidence_screen():
    """Không dựng màn hình bằng chứng thứ hai."""
    assert "def open_evidence" in UI_SRC
    assert "self.evidence_tab.open_event" in UI_SRC
    assert '"cmd": "expert_get_event"' in UI_SRC
    assert UI_SRC.count("evidence_detail_rows") >= 1
    # Không có bộ dựng chi tiết bằng chứng thứ hai trong report_view.
    source = pathlib.Path("shield/ui/report_view.py").read_text(encoding="utf-8")
    assert "evidence_detail_rows" not in source
    assert "expert_get_event" not in source


# --------------------------------------------------------------------------
# §1 + §14 phạm vi: KHÔNG chat, KHÔNG prompt, KHÔNG chọn model


def test_the_ui_has_no_chat_or_prompt_surface():
    source = pathlib.Path("shield/ui/report_view.py").read_text(encoding="utf-8")
    for forbidden in ("QLineEdit", "prompt", "chat", "message", "QTextEdit"):
        assert forbidden not in source, forbidden


def test_the_opt_in_is_a_single_boolean():
    """Không chọn model, không sửa đường dẫn, không ô nhập prompt."""
    block = UI_SRC[UI_SRC.index("def _toggle_ai_explanation"):]
    block = block[:block.index("\n    def ", 10)]
    assert '"cmd": "set_ai_explanation"' in block
    assert '"enabled": bool(enabled)' in block
    assert "model_path" not in block and "prompt" not in block


def test_the_opt_in_explains_what_it_turns_on():
    """§4: giao diện phải nói rõ BỐN điều — model cục bộ, chỉ chạy nền, chỉ
    những kịch bản đã kiểm mới có văn xuôi, và báo cáo vẫn đầy đủ khi tắt."""
    vietnamese, english = STRINGS["report.ai.opt_in_hint"]
    for phrase in ("on this machine", "background", "passed review",
                   "Reports stay complete when this is off"):
        assert phrase in english, phrase
    for phrase in ("ngay trên máy này", "nền", "kiểm đủ", "vẫn đầy đủ khi tắt"):
        assert phrase in vietnamese, phrase
    # Và nói rõ không gửi gì ra ngoài.
    assert "Nothing leaves the machine" in english
    assert "Không gửi gì ra ngoài" in vietnamese


def test_a_missing_provider_disables_the_toggle_instead_of_lying():
    block = UI_SRC[UI_SRC.index("def on_ai_explanation_state"):]
    block = block[:block.index("\n    def ", 10)]
    assert "setEnabled(False)" in block
    assert "report.ai.provider_missing" in block


# --------------------------------------------------------------------------
# §4 + §6 opt-in mặc định TẮT, và hỏi lại không sinh job mới


def _store(tmp_path):
    return Store(tmp_path / "s.db")


def _incident(store):
    store.insert_alert(Alert(NOW, "LOCAL_SSH_BRUTEFORCE", "warning", "t", "d",
                             "192.168.1.77",
                             evidence={"src_ip": "192.168.1.77", "fail_count": 37},
                             playbook=["snapshot_state"]))
    row = store.open_or_update_incident(
        correlation_id="ACCUMULATED_AUTH_FAILURES", subject="192.168.1.77",
        title="t", severity="warning", risk_score=61, evidence_strength=0.6,
        recommended_action="snapshot_state",
        contributing=[{"rule_id": "LOCAL_SSH_BRUTEFORCE", "ts": NOW,
                       "severity": "warning", "detail": ""}])
    return row["incident_id"]


def _run(store, incident_id):
    from shield.agent.__main__ import run_investigation

    return asyncio.run(run_investigation(store, incident_id))


def test_the_opt_in_defaults_to_off(tmp_path, monkeypatch):
    """Một tính năng chạy model cục bộ phải bật bằng một hành động, không phải
    tắt bằng một hành động."""
    from shield.agent.__main__ import _explanation_opt_in

    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    assert _explanation_opt_in(store) is False
    payload = _run(store, _incident(store))
    assert payload["explanation"]["opted_in"] is False
    # "disabled", không phải "ineligible": kịch bản này ĐÃ chín, thứ đang tắt
    # là công tắc của người dùng.
    assert payload["ai_enrichment"]["status"] == E.CLIENT_DISABLED
    assert EnrichmentStore(store.conn).counts() == {}


def test_ten_polls_while_pending_create_exactly_one_job(tmp_path, monkeypatch):
    """§6: hỏi lại phải dùng lại đúng job/fingerprint."""
    from shield.agent.__main__ import EXPLANATION_OPT_IN_KEY

    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    store.set_baseline(EXPLANATION_OPT_IN_KEY, "1")
    incident_id = _incident(store)

    job_ids = set()
    for _ in range(10):
        state = _run(store, incident_id)["ai_enrichment"]
        assert state["status"] == E.CLIENT_PENDING
        job_ids.add(state["job_id"])
    assert len(job_ids) == 1, f"10 lượt hỏi tạo {len(job_ids)} job"
    assert EnrichmentStore(store.conn).counts() == {E.PENDING: 1}


def test_turning_the_opt_in_off_stops_new_jobs(tmp_path, monkeypatch):
    from shield.agent.__main__ import EXPLANATION_OPT_IN_KEY

    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    store.set_baseline(EXPLANATION_OPT_IN_KEY, "1")
    incident_id = _incident(store)
    assert _run(store, incident_id)["ai_enrichment"]["status"] == E.CLIENT_PENDING
    store.set_baseline(EXPLANATION_OPT_IN_KEY, "0")
    store.conn.execute("UPDATE incidents SET risk_score=95 WHERE incident_id=?",
                       (incident_id,))
    store.conn.commit()
    assert _run(store, incident_id)["ai_enrichment"]["status"] == E.CLIENT_DISABLED


def test_the_panel_names_the_right_reason_for_each_closed_gate(tmp_path,
                                                               monkeypatch):
    """§10: ba cách để không có văn xuôi, và người vận hành phải phân biệt được.

    Gộp cả ba thành "chỉ báo cáo tất định cho kịch bản này" là đẩy người vừa
    bấm kill switch đi sửa nhầm chỗ — họ sẽ đi tìm cổng kịch bản.
    """
    from shield.agent.__main__ import EXPLANATION_OPT_IN_KEY

    store = _store(tmp_path)
    store.set_baseline(EXPLANATION_OPT_IN_KEY, "1")
    incident_id = _incident(store)

    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    assert _run(store, incident_id)["ai_enrichment"]["status"] == E.CLIENT_DISABLED

    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.setenv("SHIELD_AI_KILL_SWITCH", "1")
    killed = _run(store, incident_id)["ai_enrichment"]
    assert killed["status"] == E.CLIENT_DISABLED
    assert EnrichmentStore(store.conn).counts() == {}, "kill switch vẫn xếp job"

    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store.conn.execute(
        "UPDATE incidents SET correlation_id='SCAN_PORTSCAN' WHERE incident_id=?",
        (incident_id,))
    store.conn.commit()
    gated = _run(store, incident_id)["ai_enrichment"]
    assert gated["status"] == E.CLIENT_INELIGIBLE, gated
    assert report_view.status_line(gated, _t) != report_view.status_line(
        killed, _t), "hai lý do khác nhau hiện cùng một câu"


# --------------------------------------------------------------------------
# §10 hỏng không được chặn báo cáo


def test_a_failed_explanation_never_blocks_the_report():
    report = _report()
    rows = report_view.deterministic_rows(report, _t, _fmt)
    assert len(rows) > 5
    assert report_view.ai_rows(report, {"status": "failed"}, _t) == []
    assert report_view.status_line({"status": "failed"}, _t) == \
        _t("report.ai.state.failed")


def test_the_ui_never_opens_a_modal_for_an_ai_failure():
    block = UI_SRC[UI_SRC.index("def _render_report"):]
    block = block[:block.index("\n    def ", 10)]
    for modal in ("QMessageBox", "QDialog", "critical(", "warning("):
        assert modal not in block, modal


# --------------------------------------------------------------------------
# Không được có khoá dịch thô lọt ra màn hình
#
# Bản cài 3.0.0a1 đầu tiên trên máy thật hiện đúng bốn dòng này trong mục "Dữ
# kiện đã xác lập": `report.fact.process_identity`, `report.fact.sequence`,
# `report.fact.dropped_paths`, `report.action.snapshot_state`. Giao diện rơi về
# chính cái khoá khi khoá không có trong `STRINGS`, nên thiếu nhãn không làm gì
# đỏ — nó chỉ lặng lẽ hiện tên biến cho người đọc.


def _registry_label_keys():
    import shield.report.scenarios as scenarios

    facts, actions = set(), set()
    for scenario in scenarios.SCENARIOS:
        facts |= set(scenario.required_fact_keys)
        facts |= set(scenario.optional_fact_keys)
        actions |= set(scenario.allowed_recommendation_codes)
    return ({f"report.fact.{name}" for name in facts},
            {f"report.action.{code}" for code in actions})


def test_every_fact_and_action_the_registry_can_emit_has_a_label():
    facts, actions = _registry_label_keys()
    missing = sorted(key for key in facts | actions if key not in STRINGS)
    assert missing == [], f"khoá không có nhãn: {missing}"


def test_every_label_is_translated_in_both_languages():
    facts, actions = _registry_label_keys()
    for key in sorted(facts | actions):
        vietnamese, english = STRINGS[key]
        assert vietnamese.strip() and english.strip(), key
        # Nhãn phải là NHÃN, không phải khoá viết lại.
        assert not vietnamese.startswith("report."), key
        assert not english.startswith("report."), key


def test_a_rendered_report_never_shows_a_raw_key(tmp_path, monkeypatch):
    """Kiểm trên báo cáo THẬT, không chỉ trên bảng khoá."""
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    store = _store(tmp_path)
    payload = _run(store, _incident(store))
    rows = report_view.deterministic_rows(payload["incident_report"], _t, _fmt)
    assert rows, "báo cáo rỗng thì bài test này không chứng minh gì"
    raw = [label for label, _value, _section in rows
           if label.startswith("report.") and label not in STRINGS]
    assert raw == [], f"nhãn chưa dịch lọt ra màn hình: {raw}"
    sections = {section for _l, _v, section in rows}
    for section in sections:
        assert f"report.section.{section}" in STRINGS, section
