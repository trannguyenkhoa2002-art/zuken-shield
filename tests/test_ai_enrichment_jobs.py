"""Báo cáo tất định TRƯỚC, văn xuôi model SAU (Phase 3D rollout).

Suy luận mất ~15 giây; báo cáo tất định mất mili giây. Ghép hai thứ vào một
lời gọi nghĩa là người dùng chờ 15 giây cho một thứ đã sẵn sàng ngay từ đầu —
và khi model hỏng, họ chờ 15 giây rồi không nhận được gì.

Bất biến trung tâm của bộ này: **không bao giờ phục vụ văn xuôi cũ.** Bằng
chứng đổi, ngôn ngữ đổi, model đổi — mỗi thứ làm khoá đổi, và khoá cũ không bao
giờ khớp lại. Một đoạn giải thích đúng cho dữ liệu hôm qua là một đoạn SAI cho
dữ liệu hôm nay, và nó không tự nói ra điều đó.
"""

from __future__ import annotations

import asyncio
import pathlib
import time
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.ai import enrichment as E
from shield.ai.enrichment import EnrichmentStore, fingerprint, model_version
from shield.ai.enrichment_runner import Queue, SharedAiRunner, client_status
from shield.common.models import Alert

NOW = 1000.0


def _store(tmp_path, name="s.db"):
    """Store với phần giải thích ĐÃ BẬT TAY.

    Các test ở đây kiểm cơ chế job, không kiểm việc đồng ý: cổng opt-in có
    test riêng trong `test_report_ui.py`. Bật ở đây một cách tường minh để
    mặc-định-tắt vẫn là mặc định thật ở nơi khác.
    """
    from shield.agent.__main__ import EXPLANATION_OPT_IN_KEY
    store = Store(tmp_path / name)
    store.set_baseline(EXPLANATION_OPT_IN_KEY, "1")
    return store


def _incident(store, correlation_id="ACCUMULATED_AUTH_FAILURES",
              rule_id="LOCAL_SSH_BRUTEFORCE", fail_count=37):
    store.insert_alert(Alert(NOW, rule_id, "warning", "t", "d", "192.168.1.77",
                             evidence={"src_ip": "192.168.1.77",
                                       "fail_count": fail_count},
                             playbook=["snapshot_state"]))
    row = store.open_or_update_incident(
        correlation_id=correlation_id, subject="192.168.1.77", title="t",
        severity="warning", risk_score=61, evidence_strength=0.6,
        recommended_action="snapshot_state",
        contributing=[{"rule_id": rule_id, "ts": NOW, "severity": "warning",
                       "detail": ""}])
    return row["incident_id"] if isinstance(row, dict) else row


def _run(store, incident_id):
    from shield.agent.__main__ import run_investigation

    return asyncio.run(run_investigation(store, incident_id))


def _key(store, incident_id, locale="vi", provider="local_model"):
    from shield.agent.__main__ import enrichment_key
    from shield.report.incident import build

    return enrichment_key(store, incident_id, build(store, incident_id, locale=locale),
                          locale, provider)[0]


# --------------------------------------------------------------------------
# §1 ngữ nghĩa người dùng thấy


def test_a_disabled_provider_returns_immediately_and_creates_no_job(
        tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "disabled")
    store = _store(tmp_path)
    payload = _run(store, _incident(store))
    assert payload["ai_enrichment"]["status"] == E.CLIENT_DISABLED
    assert EnrichmentStore(store.conn).counts() == {}
    assert payload["incident_report"]["severity"]["level"] == "warning"


def test_an_ineligible_scenario_returns_immediately_and_creates_no_job(
        tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    payload = _run(store, _incident(store, "CORRELATED_NEW_DEVICE_THEN_SCAN",
                                    "SCAN_PORTSCAN"))
    assert payload["ai_enrichment"]["status"] == E.CLIENT_INELIGIBLE
    assert EnrichmentStore(store.conn).counts() == {}


def test_an_eligible_scenario_enqueues_and_returns_pending(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    payload = _run(store, _incident(store))
    state = payload["ai_enrichment"]
    assert state["status"] == E.CLIENT_PENDING and state["job_id"]
    assert EnrichmentStore(store.conn).counts() == {E.PENDING: 1}
    # Báo cáo tất định đầy đủ NGAY, không chờ model.
    assert payload["incident_report"]["confirmed_facts"]
    assert payload["incident_report"]["analysis"]["ai_generated"] is False


def test_the_response_is_fast_even_though_inference_is_slow(tmp_path, monkeypatch):
    """§10: model mất 20 giây, phản hồi đầu tiên vẫn phải nhanh."""
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    incident_id = _incident(store)
    started = time.perf_counter()
    payload = _run(store, incident_id)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"phản hồi mất {elapsed:.1f}s — có ai đó đang chờ model"
    assert payload["ai_enrichment"]["status"] == E.CLIENT_PENDING


def test_the_client_status_set_is_closed():
    assert E.CLIENT_STATUSES == {"disabled", "ineligible", "pending", "ready",
                                 "failed", "deferred"}
    assert E.STATUSES == {"pending", "running", "ready", "failed", "stale"}


# --------------------------------------------------------------------------
# §4 khoá đồng nhất


def test_the_same_request_twice_creates_one_job(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    incident_id = _incident(store)
    first = _run(store, incident_id)["ai_enrichment"]
    second = _run(store, incident_id)["ai_enrichment"]
    assert first["job_id"] == second["job_id"]
    assert EnrichmentStore(store.conn).counts() == {E.PENDING: 1}


def test_a_different_locale_is_a_different_job(tmp_path):
    store = _store(tmp_path)
    incident_id = _incident(store)
    assert _key(store, incident_id, "vi") != _key(store, incident_id, "en")


def test_changed_evidence_changes_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    store = _store(tmp_path)
    incident_id = _incident(store, fail_count=37)
    before = _key(store, incident_id)
    store.conn.execute("UPDATE incidents SET severity='critical' WHERE incident_id=?",
                       (incident_id,))
    store.conn.commit()
    assert _key(store, incident_id) != before


def test_a_changed_model_version_changes_the_key():
    from shield.ai.model_config import ModelConfig

    base = ModelConfig(model_path="/opt/shield/models/a.gguf")
    other = ModelConfig(model_path="/opt/shield/models/b.gguf")
    assert model_version(base) != model_version(other)
    assert model_version(ModelConfig(temperature=0.0)) != \
        model_version(ModelConfig(temperature=0.7))


def test_the_key_covers_every_output_affecting_input():
    """Thiếu một thành phần nghĩa là có một cách để dữ liệu đổi mà khoá không
    đổi — và khi đó Shield phục vụ giải thích đúng cho dữ liệu của hôm qua."""
    base = dict(incident_id="i", evidence={"a": 1}, locale="vi",
                provider="local_model", model_version="m1")
    reference = fingerprint(**base)
    for field, value in (("incident_id", "j"), ("evidence", {"a": 2}),
                         ("locale", "en"), ("provider", "other"),
                         ("model_version", "m2")):
        assert fingerprint(**{**base, field: value}) != reference, field
    assert fingerprint(**base, contract_version=2) != reference


def test_a_ready_row_with_a_different_key_is_never_served(tmp_path):
    """Không bao giờ nới lỏng phép so: một hàng `ready` với khoá khác là văn
    xuôi của một dữ liệu khác."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="key-A", locale="vi",
                          provider="p", model_version_value="m")
    jobs.finish_ready(job.job_id, {"analysis": "văn xuôi cho dữ liệu A"})
    assert jobs.ready_slots("key-A")["analysis"] == "văn xuôi cho dữ liệu A"
    assert jobs.ready_slots("key-B") == {}


def test_ready_prose_is_attached_only_on_an_exact_key_match(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    incident_id = _incident(store)
    _run(store, incident_id)
    jobs = EnrichmentStore(store.conn)
    key = _key(store, incident_id)
    job = jobs.by_fingerprint(key)
    jobs.finish_ready(job.job_id, {"analysis": "Có thể là dò mật khẩu.",
                                   "why_this_matters": "Đáng xem."})
    payload = _run(store, incident_id)
    assert payload["ai_enrichment"]["status"] == E.CLIENT_READY
    assert payload["incident_report"]["analysis"]["prose"] == "Có thể là dò mật khẩu."
    assert payload["incident_report"]["analysis"]["ai_generated"] is True

    # Bằng chứng đổi -> khoá đổi -> văn xuôi cũ KHÔNG được gắn lại.
    store.conn.execute("UPDATE incidents SET risk_score=99 WHERE incident_id=?",
                       (incident_id,))
    store.conn.commit()
    after = _run(store, incident_id)
    assert after["incident_report"]["analysis"]["prose"] == ""
    assert after["ai_enrichment"]["status"] != E.CLIENT_READY


# --------------------------------------------------------------------------
# §3 trần


def test_a_full_queue_never_blocks_the_deterministic_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    for index in range(E.MAX_QUEUED):
        jobs.enqueue(incident_id=f"filler-{index}", fingerprint_value=f"fp-{index}",
                     locale="vi", provider="p", model_version_value="m")
    payload = _run(store, _incident(store))
    assert payload["ai_enrichment"]["status"] == E.CLIENT_DEFERRED
    assert payload["ai_enrichment"]["failure_code"] == "queue_full"
    # ...và báo cáo vẫn đầy đủ.
    assert payload["incident_report"]["confirmed_facts"]
    assert payload["incident_report"]["severity"]["level"] == "warning"


def test_only_one_job_runs_at_a_time(tmp_path):
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    for index in range(3):
        jobs.enqueue(incident_id=f"i{index}", fingerprint_value=f"fp{index}",
                     locale="vi", provider="p", model_version_value="m")
    assert jobs.claim() is not None
    assert jobs.claim() is None, "MAX_CONCURRENT = 1"


def test_the_bounds_are_the_agreed_ones():
    assert E.MAX_CONCURRENT == 1
    assert E.MAX_QUEUED == 16
    assert E.MAX_ATTEMPTS == 2


# --------------------------------------------------------------------------
# §5 vòng đời và khởi động lại


def test_a_running_job_from_a_dead_process_is_reconciled(tmp_path):
    """`RUNNING` cũ KHÔNG còn chạy — tiến trình sở hữu nó đã chết. Giả vờ nó
    vẫn chạy nghĩa là hàng đợi tắc mãi mãi."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                          provider="p", model_version_value="m")
    jobs.claim()
    assert jobs.get(job.job_id).status == E.RUNNING
    result = jobs.reconcile_startup()
    assert result["revived"] == 1
    assert jobs.get(job.job_id).status == E.PENDING


def test_a_job_that_exhausted_its_attempts_is_abandoned_not_revived(tmp_path):
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                          provider="p", model_version_value="m")
    for _ in range(E.MAX_ATTEMPTS):
        jobs.claim()
        store.conn.execute("UPDATE ai_enrichment_jobs SET status=? WHERE job_id=?",
                           (E.PENDING, job.job_id))
        store.conn.commit()
    store.conn.execute("UPDATE ai_enrichment_jobs SET status=? WHERE job_id=?",
                       (E.RUNNING, job.job_id))
    store.conn.commit()
    result = jobs.reconcile_startup()
    assert result["abandoned"] == 1
    assert jobs.get(job.job_id).status == E.FAILED


def test_a_stale_pending_job_expires(tmp_path):
    clock = [NOW]
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn, clock=lambda: clock[0])
    jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                 provider="p", model_version_value="m")
    clock[0] = NOW + E.STALE_RUNNING_S + 1
    assert jobs.reconcile_startup()["expired"] == 1


def test_the_runner_returns_a_cancelled_job_to_the_queue(tmp_path):
    """Agent tắt giữa chừng KHÔNG được để lại `running` mồ côi."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                          provider="p", model_version_value="m")

    async def cancelled(_job):
        raise asyncio.CancelledError

    runner = SharedAiRunner(Queue('enrichment', jobs, cancelled))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(runner.tick())
    assert jobs.get(job.job_id).status in (E.PENDING, E.FAILED)


def test_a_stale_fingerprint_result_is_discarded(tmp_path):
    """Bằng chứng đổi TRONG LÚC suy luận -> kết quả nói về dữ liệu không còn
    tồn tại, nên nó không được gắn vào đâu cả."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                          provider="p", model_version_value="m")

    async def stale(_job):
        return None, ""

    asyncio.run(SharedAiRunner(Queue('enrichment', jobs, stale)).tick())
    assert jobs.get(job.job_id).status == E.STALE
    assert jobs.ready_slots("fp") == {}


# --------------------------------------------------------------------------
# §8 hỏng


@pytest.mark.parametrize("code,expected_status", [
    ("provider_unavailable", E.FAILED),
    ("malformed_output", E.FAILED),
    ("validation_failed", E.FAILED),
    ("kill_switch", E.FAILED),
    ("timeout", E.PENDING),        # còn lượt thử -> quay lại hàng đợi
])
def test_failure_codes_are_closed_and_drive_retry(tmp_path, code, expected_status):
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                          provider="p", model_version_value="m")
    jobs.claim()
    jobs.finish_failed(job.job_id, code)
    row = jobs.get(job.job_id)
    assert row.status == expected_status
    assert row.failure_code in E.FAILURE_CODES


def test_an_unknown_failure_code_becomes_internal_error(tmp_path):
    """Không câu ngoại lệ thô nào lọt ra: thông điệp ngoại lệ do mã model sinh
    và có thể chứa bất cứ thứ gì."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                          provider="p", model_version_value="m")
    jobs.claim()
    jobs.finish_failed(job.job_id, "AKIAIOSFODNN7EXAMPLE nổ ở dòng 42")
    assert jobs.get(job.job_id).failure_code == "internal_error"


def test_a_worker_crash_leaves_the_report_untouched(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    incident_id = _incident(store)
    baseline = _run(store, incident_id)["incident_report"]
    jobs = EnrichmentStore(store.conn)
    job = jobs.by_fingerprint(_key(store, incident_id))
    jobs.claim()
    jobs.finish_failed(job.job_id, "resource_limit")
    after = _run(store, incident_id)
    for section in baseline["deterministic_sections"]:
        if section == "limitations":
            continue
        assert after["incident_report"][section] == baseline[section], section


# --------------------------------------------------------------------------
# §2 kho hẹp, không rò


def test_only_validated_slots_are_persisted(tmp_path):
    """Không lưu output thô: bản thô đã có `InvestigationAudit` giữ, và giữ hai
    bản là mở hai chỗ để rò."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    job, _ = jobs.enqueue(incident_id="i", fingerprint_value="fp", locale="vi",
                          provider="p", model_version_value="m")
    jobs.finish_ready(job.job_id, {
        "analysis": "an toàn", "raw_output": "AKIAIOSFODNN7EXAMPLE",
        "tool_observations": [1, 2, 3], "token": "bí mật"})
    row = store.conn.execute("SELECT slots FROM ai_enrichment_jobs WHERE job_id=?",
                             (job.job_id,)).fetchone()[0]
    assert "AKIA" not in row and "token" not in row and "tool_observations" not in row
    assert set(jobs.get(job.job_id).slots) == {
        "analysis", "hypothesis_rationale", "why_this_matters"}


def test_the_store_does_not_reuse_the_response_job_machinery():
    """Kiểm MÃ, không kiểm tài liệu — module này GIẢI THÍCH vì sao nó không
    dùng lại `ResponseJobStore`, và tìm chuỗi thô sẽ phạt đúng lời giải thích."""
    from tests._srcheck import code_only

    source = code_only("shield/ai/enrichment.py")
    assert "ResponseJobStore" not in source
    assert "response_jobs" not in source
    raw = pathlib.Path("shield/ai/enrichment.py").read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS ai_enrichment_jobs" in raw


def test_the_runner_is_not_a_general_background_framework():
    import inspect

    import shield.ai.enrichment_runner as module

    source = inspect.getsource(module)
    assert "register" not in source and "scheduler" not in source
    assert source.count("async def ") <= 4  # _loop, tick, stop


# --------------------------------------------------------------------------
# §12 không có suy luận nào trong vòng đọc IPC


def test_no_model_inference_happens_on_the_ipc_path():
    """`await self._on_command(msg)` chạy trong vòng đọc của một kết nối. Suy
    luận ở đó khoá mọi lệnh tiếp theo của client đó."""
    import inspect

    from shield.agent.__main__ import run_investigation

    source = inspect.getsource(run_investigation)
    assert 'select_provider("disabled")' in source, \
        "đường đồng bộ phải luôn dùng provider tắt"
    assert "LocalModelAnalyst" not in source


# --------------------------------------------------------------------------
# §8 buộc `contract_version` vào thứ nó phải theo dõi


def test_the_contract_digest_pins_prompt_grammar_and_slot_shape():
    """Một hằng số tăng bằng tay là một hằng số có người quên tăng — và quên ở
    đây nghĩa là văn xuôi sinh bởi prompt cũ vẫn được phục vụ như thể còn đúng.

    Bài này băm ba artefact quyết định hình dạng đầu ra. Đổi bất kỳ cái nào mà
    không tăng `CONTRACT_VERSION` sẽ làm bài đỏ, kèm digest mới để dán vào.
    """
    assert E.contract_digest() == E.CONTRACT_DIGEST, (
        f"prompt/ngữ pháp/hợp đồng ô đã đổi. Tăng CONTRACT_VERSION rồi đặt "
        f"CONTRACT_DIGEST = {E.contract_digest()!r}")


def test_changing_the_contract_version_invalidates_old_prose():
    base = dict(incident_id="i", evidence={"a": 1}, locale="vi",
                provider="local_model", model_version="m")
    assert fingerprint(**base, contract_version=1) != \
        fingerprint(**base, contract_version=2)


def test_the_worker_honours_explanation_only_mode():
    """Nhánh này từng thiếu, và thiếu theo kiểu IM LẶNG: worker chạy prompt
    điều tra, trả về một `InvestigationResult` không có khoá `analysis`, và
    adapter đọc ra ba chuỗi rỗng. Không lỗi nào được ném, không cổng nào chặn —
    văn xuôi chỉ đơn giản không bao giờ xuất hiện.

    Chỉ một lượt chạy model THẬT mới lộ ra được: mọi test kịch bản trước đó
    tiêm sẵn output, nên chúng không bao giờ đi qua nhánh này.
    """
    import inspect

    import shield.ai.worker.__main__ as W

    source = inspect.getsource(W._analyse_with_model)
    assert 'config.mode == "explanation_only"' in source
    assert "build_explanation_prompt" in source
    assert "explanation_grammar" in source
    # Và nó trả về ĐÚNG ba ô, không phải hình dạng điều tra.
    assert '"analysis", "hypothesis_rationale", "why_this_matters"' in source


def test_the_epistemic_state_reaches_the_worker():
    """Guard ở đường ra vẫn kiểm độc lập, nhưng model được nói trước sẽ vi phạm
    ít hơn — và mỗi lần không vi phạm là một lần không phải bỏ cả ô."""
    import inspect

    from shield.agent.__main__ import execute_enrichment_job

    assert '"epistemic_state"' in inspect.getsource(execute_enrichment_job)


def test_aggregated_scenarios_carry_their_own_facts():
    """Lỗi thật: một incident gộp từ `BEHAVIOR_EXEC_WRITE_CONNECT` ra kịch bản
    `SUSPICIOUS_EXECUTION_CHAIN` với `confirmed_facts` RỖNG — trong khi alert
    bên dưới có đủ `process_identity` và `sequence`. Báo cáo mỏng đi vì đọc sai
    chỗ, không phải vì thiếu dữ liệu."""
    from shield.report.incident import scenario_facts

    store = _store(Path(__import__("tempfile").mkdtemp()))
    store.insert_alert(Alert(NOW, "BEHAVIOR_EXEC_WRITE_CONNECT", "warning", "t", "d",
                             "host", evidence={"process_identity": "1:2",
                                               "sequence": ["process_exec"],
                                               "khong_khai_bao": "bỏ qua"},
                             playbook=["snapshot_state"]))
    row = store.open_or_update_incident(
        correlation_id="KHONG_CO_ANH_XA", subject="host", title="t",
        severity="warning", risk_score=1, evidence_strength=0.5,
        recommended_action="snapshot_state",
        contributing=[{"rule_id": "BEHAVIOR_EXEC_WRITE_CONNECT", "ts": NOW,
                       "severity": "warning", "detail": ""}])
    incident_id = row["incident_id"]
    facts = scenario_facts(store, incident_id, "SUSPICIOUS_EXECUTION_CHAIN")
    assert facts["process_identity"] == "1:2"
    assert facts["sequence"] == ["process_exec"]
    # Chỉ khoá kịch bản KHAI BÁO — không đổ cả evidence của alert vào báo cáo.
    assert "khong_khai_bao" not in facts

    from shield.report.incident import build

    report = build(store, incident_id)
    assert report["incident_type"]["scenario_code"] == "SUSPICIOUS_EXECUTION_CHAIN"
    assert report["missing_required_facts"] == []
    assert report["confirmed_facts"]["process_identity"] == "1:2"
    # Khuôn chỉ lấy khoá KỊCH BẢN KHAI BÁO, nên lớp incident (`rules`,
    # `observed_count`) không xuất hiện ở kịch bản này — nó chỉ xuất hiện ở
    # những kịch bản tương quan có khai chúng.
    assert "rules" not in report["confirmed_facts"]


def test_a_correlated_scenario_still_gets_the_incident_layer():
    """Bài đối chứng cho bài trên: lớp incident KHÔNG bị lớp kịch bản đè mất."""
    from shield.report.incident import build

    store = _store(Path(__import__("tempfile").mkdtemp()))
    incident_id = _incident(store)
    report = build(store, incident_id)
    assert report["incident_type"]["scenario_code"] == "REPEATED_AUTH_FAILURES"
    assert report["confirmed_facts"]["rules"] == ["LOCAL_SSH_BRUTEFORCE"]
    assert report["confirmed_facts"]["observed_count"] == 1


# --------------------------------------------------------------------------
# B1 — số lượt suy luận phải bị chặn theo KHOÁ, không theo hàng
#
# Lỗi gốc: `enqueue` chỉ dùng lại `PENDING/RUNNING/READY`, nên một hàng `FAILED`
# bị bỏ qua và mỗi lượt mở lại đúc một hàng mới `attempts=0`. Đo được: 5 lượt mở
# -> 5 job_id khác nhau, mỗi cái `attempts=0`, và giao diện không bao giờ hiện
# `failed` vì nó luôn đọc đúng cái hàng vừa được tạo.


def _fail_once(jobs, key, code, *, incident="i1"):
    """Xếp hàng -> chạy -> hỏng. Trả về hàng sau khi hỏng."""
    job, _reason = jobs.enqueue(incident_id=incident, fingerprint_value=key,
                                locale="vi", provider="local_model",
                                model_version_value="v1")
    assert job is not None
    claimed = jobs.claim()
    assert claimed is not None, "không lấy được job vừa xếp"
    jobs.finish_failed(claimed.job_id, code)
    return jobs.by_fingerprint(key)


@pytest.mark.parametrize("code", ["malformed_output", "provider_unavailable",
                                  "validation_failed", "kill_switch"])
def test_a_non_retryable_failure_never_runs_again_on_reopen(tmp_path, code):
    """§5: 5 lượt mở lại trên CÙNG khoá -> đúng 1 job, không lượt suy luận nào thêm."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    key = "MOT-KHOA-DUY-NHAT"

    _fail_once(jobs, key, code)
    after_first = jobs.by_fingerprint(key)
    assert after_first.status == E.FAILED
    attempts_after_failure = after_first.attempts

    seen = set()
    for _ in range(5):                      # người dùng mở lại 5 lần
        job, reason = jobs.enqueue(incident_id="i1", fingerprint_value=key,
                                   locale="vi", provider="local_model",
                                   model_version_value="v1")
        assert job is not None
        assert reason == "reused", f"lượt mở lại đúc hàng mới: {reason}"
        seen.add(job.job_id)
        assert jobs.claim() is None, "hàng FAILED vẫn được đem đi chạy lại"

    assert len(seen) == 1, f"5 lượt mở tạo {len(seen)} job"
    assert jobs.counts() == {E.FAILED: 1}, jobs.counts()
    final = jobs.by_fingerprint(key)
    assert final.status == E.FAILED
    assert final.failure_code == code
    assert final.attempts == attempts_after_failure <= E.MAX_ATTEMPTS


def test_a_retryable_failure_gets_exactly_max_attempts_then_stays_failed(tmp_path):
    """§5: đúng `MAX_ATTEMPTS` lượt suy luận cho một khoá, rồi đứng yên."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    key = "KHOA-TIMEOUT"

    job, _ = jobs.enqueue(incident_id="i1", fingerprint_value=key, locale="vi",
                          provider="local_model", model_version_value="v1")
    runs = 0
    while (claimed := jobs.claim()) is not None:
        runs += 1
        jobs.finish_failed(claimed.job_id, "timeout")
        assert runs <= 10, "vòng lặp không dừng"

    assert runs == E.MAX_ATTEMPTS, f"chạy {runs} lượt, chờ {E.MAX_ATTEMPTS}"
    row = jobs.by_fingerprint(key)
    assert row.status == E.FAILED and row.attempts == E.MAX_ATTEMPTS
    assert row.job_id == job.job_id, "lượt thử lại đúc hàng mới thay vì dùng lại"

    # Mở lại sau khi cạn lượt: không thêm lượt nào nữa.
    for _ in range(5):
        again, reason = jobs.enqueue(incident_id="i1", fingerprint_value=key,
                                     locale="vi", provider="local_model",
                                     model_version_value="v1")
        assert reason == "reused" and again.job_id == job.job_id
        assert jobs.claim() is None
    assert jobs.by_fingerprint(key).attempts == E.MAX_ATTEMPTS


def test_a_failed_job_survives_a_restart_with_its_attempt_history(tmp_path):
    """§7: `FAILED` vẫn là `FAILED` sau khởi động lại, và lượt đã dùng không bị xoá."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    key = "KHOA-KHOI-DONG-LAI"
    _fail_once(jobs, key, "malformed_output")
    before = jobs.by_fingerprint(key)

    reborn = EnrichmentStore(store.conn)     # như một tiến trình mới
    report = reborn.reconcile_startup()
    assert report["revived"] == 0 and report["abandoned"] == 0

    after = reborn.by_fingerprint(key)
    assert after.status == E.FAILED
    assert after.job_id == before.job_id
    assert after.attempts == before.attempts
    assert reborn.claim() is None, "khởi động lại làm job hỏng chạy lại"


def test_a_genuinely_new_fingerprint_is_not_blocked_by_an_old_failure(tmp_path):
    """§8: khoá mới là câu hỏi mới, không phải lượt thử lại của khoá cũ."""
    store = _store(tmp_path)
    jobs = EnrichmentStore(store.conn)
    _fail_once(jobs, "KHOA-CU", "malformed_output")

    fresh, reason = jobs.enqueue(incident_id="i1", fingerprint_value="KHOA-MOI",
                                 locale="vi", provider="local_model",
                                 model_version_value="v2")
    assert reason == "created" and fresh.status == E.PENDING
    assert fresh.attempts == 0, "khoá mới thừa kế lịch sử của khoá cũ"
    assert jobs.claim() is not None, "khoá mới không được chạy"
    assert jobs.counts() == {E.FAILED: 1, E.RUNNING: 1}


def test_every_input_that_changes_the_answer_makes_a_new_key(tmp_path):
    """§8: đổi bằng chứng/ngôn ngữ/model/hợp đồng -> khoá khác, nên được hỏi lại."""
    base = dict(incident_id="i1", evidence={"a": 1}, locale="vi",
                provider="local_model", model_version="v1")
    key = fingerprint(**base)
    for field, value in [("evidence", {"a": 2}), ("locale", "en"),
                         ("provider", "other"), ("model_version", "v2"),
                         ("incident_id", "i2")]:
        assert fingerprint(**{**base, field: value}) != key, field
    assert fingerprint(**base, contract_version=E.CONTRACT_VERSION + 1) != key
    assert fingerprint(**base) == key, "cùng đầu vào phải ra cùng khoá"


def test_the_ui_sees_failed_instead_of_a_freshly_minted_pending(tmp_path, monkeypatch):
    """§4: sau một lượt hỏng, `investigate_incident` phải NÓI là hỏng.

    Đây là nửa thứ hai của B1: xếp hàng trước rồi mới đọc trạng thái nghĩa là
    trạng thái đọc được luôn thuộc về cái hàng vừa tạo, nên `failed` không bao
    giờ tới được người dùng.
    """
    monkeypatch.setenv("SHIELD_AI_PROVIDER", "local_model")
    monkeypatch.delenv("SHIELD_AI_KILL_SWITCH", raising=False)
    store = _store(tmp_path)
    incident_id = _incident(store)
    jobs = EnrichmentStore(store.conn)

    first = _run(store, incident_id)["ai_enrichment"]
    assert first["status"] == E.CLIENT_PENDING
    claimed = jobs.claim()
    jobs.finish_failed(claimed.job_id, "malformed_output")

    for poll in range(6):
        state = _run(store, incident_id)["ai_enrichment"]
        assert state["status"] == E.CLIENT_FAILED, f"lượt {poll}: {state['status']}"
        assert state["failure_code"] == "malformed_output"
        assert state["job_id"] == claimed.job_id
        # Báo cáo tất định vẫn dùng được bình thường.
        assert _run(store, incident_id)["incident_report"]["confirmed_facts"]

    assert jobs.counts() == {E.FAILED: 1}, jobs.counts()
    assert jobs.claim() is None


def test_polling_stops_on_every_terminal_state():
    """§6: chỉ `pending` mới đáng hỏi lại. `failed` không được kéo vòng lặp."""
    from shield.ui import report_view

    for status in (E.CLIENT_FAILED, E.CLIENT_READY, E.CLIENT_DEFERRED,
                   E.CLIENT_DISABLED, E.CLIENT_INELIGIBLE):
        assert report_view.should_poll({"status": status}) is False, status
    assert report_view.should_poll({"status": E.CLIENT_PENDING}) is True


# --------------------------------------------------------------------------
# Mã hỏng của worker phải đi tới người vận hành nguyên vẹn
#
# Máy cài 3.0.0a1 đầu tiên chưa có `llama-cpp-python` TRONG venv của agent.
# Worker nói đúng: `runtime_unavailable`. Agent vứt nó đi và báo
# `malformed_output`, nên người vận hành đọc được "model sinh ra rác" và đi tìm
# lỗi chất lượng model thay vì đi cài runtime.


def test_an_in_band_worker_failure_keeps_its_own_code():
    from shield.agent.__main__ import _job_failure_code

    assert _job_failure_code("runtime_unavailable") == "provider_unavailable"
    assert _job_failure_code("model_missing") == "provider_unavailable"
    assert _job_failure_code("scope_unavailable") == "provider_unavailable"
    assert _job_failure_code("network_isolation_failed") == "provider_unavailable"
    assert _job_failure_code("timeout") == "timeout"
    assert _job_failure_code("resource_limit") == "resource_limit"
    assert _job_failure_code("malformed_frame") == "malformed_output"
    assert _job_failure_code("kill_switch") == "kill_switch"
    # Mã lạ KHÔNG được đoán thành một lý do nghe hợp lý.
    assert _job_failure_code("chua_tung_thay") == "internal_error"
    assert _job_failure_code("") == "internal_error"


def test_every_code_the_worker_can_send_maps_to_a_real_job_code():
    from shield.agent.__main__ import _WORKER_FAILURE_CODES, _job_failure_code
    from shield.ai.worker.protocol import FAILURE_CODES

    for code in FAILURE_CODES:
        if code in {"ok", "busy", "protocol_mismatch", "worker_exit",
                    "pipe_closed", "crashed"}:
            continue        # không phải lý do TỪ CHỐI, đi nhánh ngoại lệ
        assert code in _WORKER_FAILURE_CODES, f"worker gửi được {code} mà agent không biết"
    for mapped in _WORKER_FAILURE_CODES.values():
        assert mapped in E.FAILURE_CODES, mapped
    assert _job_failure_code("crashed") == "internal_error"


def test_the_two_failure_paths_agree():
    """Ném ra hay trả về trong băng — cùng một bảng, nên cùng một câu trả lời.

    Kiểm trên AST chứ không tìm chuỗi trong nguồn: chú thích ngay trên chỗ sửa
    có nhắc tên mã cũ, và một bài test tìm chuỗi sẽ đỏ vì chính lời giải thích
    đó — rồi cách sửa rẻ nhất là xoá lời giải thích.
    """
    import ast
    import inspect
    import textwrap

    from shield.agent import __main__ as agent

    tree = ast.parse(textwrap.dedent(inspect.getsource(agent.execute_enrichment_job)))
    constants, calls = [], 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        # Mỗi nhánh hỏng trả về `(None, <mã>)`.
        if not (isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2):
            continue
        code = node.value.elts[1]
        if isinstance(code, ast.Call) and getattr(code.func, "id", "") == "_job_failure_code":
            calls += 1
        elif isinstance(code, ast.Constant):
            constants.append(code.value)

    assert calls == 2, f"chỉ {calls} nhánh dùng bảng chung"
    # Các hằng còn lại là những lý do agent tự biết, KHÔNG phải mã của worker.
    assert set(constants) <= {"", "kill_switch", "provider_unavailable",
                              "validation_failed"}, constants
