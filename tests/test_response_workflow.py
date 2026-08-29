"""Response workflow bền vững và Verification Agent (Phase 4).

Gate của phase:

- Kill agent tại mọi state vẫn recover hoặc rollback đúng.
- Duplicate command không nhân đôi action.
- Verification failure tự rollback action reversible theo policy.
- Rollback failure tạo critical system incident và notify ngoài agent.
- UI hiển thị toàn bộ transition và evidence hậu kiểm.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.response.adapters.base import (
    ApplyResult,
    CheckResult,
    Impact,
    RollbackResult,
    VerificationResult,
)
from shield.response.adapters.temporary_block import TemporaryBlockAdapter, protected_reason
from shield.response.executor import ResponseExecutorV2
from shield.response.jobs import (
    TERMINAL,
    TRANSITIONS,
    UNFINISHED,
    JobState,
    ResponseJobStore,
    TransitionError,
    is_terminal,
    next_states,
)

ROOT = Path(__file__).resolve().parent.parent


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "shield.db", allow_migration=True)


@pytest.fixture()
def jobs(store):
    return ResponseJobStore(store.conn)


# --- máy trạng thái ---


def test_every_state_is_reachable_and_declared():
    declared = set(TRANSITIONS)
    assert declared == JobState.ALL, JobState.ALL - declared
    reachable = {JobState.PROPOSED}
    changed = True
    while changed:
        changed = False
        for state in list(reachable):
            for target in next_states(state):
                if target not in reachable:
                    reachable.add(target)
                    changed = True
    assert reachable == JobState.ALL, f"không tới được: {JobState.ALL - reachable}"


def test_terminal_states_have_no_way_out():
    for state in TERMINAL:
        assert next_states(state) == frozenset(), state
        assert is_terminal(state)


def test_a_failed_rollback_can_always_be_retried():
    """Bỏ cuộc ở ROLLBACK_FAILED nghĩa là để lại một luật firewall không ai gỡ."""
    assert JobState.ROLLING_BACK in next_states(JobState.ROLLBACK_FAILED)
    assert not is_terminal(JobState.ROLLBACK_FAILED)


def test_verified_is_not_the_end_because_ttl_still_has_to_run_out():
    assert JobState.ROLLING_BACK in next_states(JobState.VERIFIED)


def test_the_unfinished_set_is_exactly_the_states_that_touch_the_system():
    """Trạng thái mà agent chết ở đó sẽ để lại việc dang dở trên hệ thống thật."""
    assert UNFINISHED == {JobState.APPLYING, JobState.APPLIED,
                          JobState.VERIFYING, JobState.ROLLING_BACK}


def test_an_illegal_transition_is_refused_with_a_useful_message(jobs):
    job, _ = jobs.create(idempotency_key="k1", action="block_ip", target={"ip": "1.2.3.4"})
    with pytest.raises(TransitionError) as info:
        jobs.transition(job.job_id, JobState.VERIFIED)
    assert "PROPOSED" in str(info.value)
    assert "chỉ có thể" in str(info.value)


def test_repeating_the_current_state_is_a_no_op_not_an_error(jobs):
    """Một lượt thử lại sau khi mất kết nối sẽ làm đúng chuyện này."""
    job, _ = jobs.create(idempotency_key="k1", action="block_ip", target={})
    assert jobs.transition(job.job_id, JobState.PROPOSED).state == JobState.PROPOSED


# --- chống trùng ---


def test_the_same_command_twice_creates_one_job(jobs):
    """Gate: duplicate command không nhân đôi action."""
    first, created_first = jobs.create(idempotency_key="same", action="block_ip",
                                       target={"ip": "1.2.3.4"})
    second, created_second = jobs.create(idempotency_key="same", action="block_ip",
                                         target={"ip": "1.2.3.4"})
    assert created_first is True and created_second is False
    assert first.job_id == second.job_id
    assert len(jobs.list_jobs()) == 1


def test_a_job_without_an_idempotency_key_is_refused(jobs):
    with pytest.raises(ValueError):
        jobs.create(idempotency_key="", action="block_ip", target={})


def test_the_database_enforces_uniqueness_not_just_the_check(store, jobs):
    """Kiểm bằng SELECT trước INSERT vẫn có khe hở giữa hai tiến trình."""
    indexes = [row[0] for row in store.conn.execute(
        "SELECT sql FROM sqlite_master WHERE type IN ('table','index') "
        "AND sql LIKE '%idempotency_key%'")]
    assert any("UNIQUE" in (sql or "") for sql in indexes)


# --- lịch sử chỉ thêm ---


def test_the_transition_log_is_append_only_in_the_source():
    """Một dòng chuyển trạng thái sai vẫn phải nằm đó — nó là bằng chứng."""
    offenders = []
    for path in sorted((ROOT / "shield").glob("**/*.py")):
        text = path.read_text(encoding="utf-8")
        for statement in ("UPDATE response_transitions", "DELETE FROM response_transitions",
                          "UPDATE verification_results", "DELETE FROM verification_results"):
            if statement in text:
                offenders.append(f"{path.relative_to(ROOT)}: {statement}")
    assert offenders == [], offenders


def test_every_transition_is_recorded_with_who_did_it(jobs):
    job, _ = jobs.create(idempotency_key="k", action="block_ip", target={})
    jobs.transition(job.job_id, JobState.APPROVED, actor="khoa", detail="duyệt tay")
    history = jobs.transitions(job.job_id)
    assert [(h["from_state"], h["to_state"]) for h in history] == [
        ("", JobState.PROPOSED), (JobState.PROPOSED, JobState.APPROVED)]
    assert history[-1]["actor"] == "khoa"


def test_state_and_history_move_together(store, jobs):
    """Nửa vời nghĩa là lịch sử nói một đằng, trạng thái nói một nẻo, và không
    ai biết bên nào đúng."""
    job, _ = jobs.create(idempotency_key="k", action="block_ip", target={})
    jobs.transition(job.job_id, JobState.APPROVED, actor="a")
    assert jobs.get(job.job_id).state == JobState.APPROVED
    assert jobs.transitions(job.job_id)[-1]["to_state"] == JobState.APPROVED


# --- adapter ---


class FakeHelper:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    async def call(self, action, params):
        self.calls.append((action, dict(params)))
        return self.responses.get(action, {"ok": True, "message": ""})


def _nft(ips):
    return json.dumps({"nftables": [
        {"set": {"table": "shield", "name": "blocked_ips",
                 "elem": [{"elem": {"val": ip}} for ip in ips]}}]})


def _adapter(helper, ips=(), **kwargs):
    async def reader():
        return _nft(ips)
    return TemporaryBlockAdapter(helper, nft_reader=reader, **kwargs)


@pytest.mark.parametrize("target,reason_word", [
    ("127.0.0.1", "bảo vệ"),
    ("224.0.0.1", "multicast"),
    ("192.168.1.1", "gateway"),
    ("8.8.8.8", "DNS"),
    ("192.168.1.20", "quản trị"),
    ("khong-phai-ip", "không hợp lệ"),
])
def test_protected_addresses_are_never_blocked(target, reason_word):
    """Chặn gateway thì cả máy mất mạng; chặn DNS thì mọi thứ dựa vào tên miền
    hỏng; chặn địa chỉ quản trị thì không ai vào sửa được."""
    reason = protected_reason(target, gateway="192.168.1.1", resolvers=("8.8.8.8",),
                              management="192.168.1.20")
    assert reason and reason_word in reason


def test_an_ordinary_address_is_allowed():
    assert protected_reason("203.0.113.9", gateway="192.168.1.1") == ""


def test_a_block_without_a_ttl_is_refused():
    """Chặn không có hạn là chặn vĩnh viễn, và không ai nhớ để gỡ."""
    check = run(_adapter(FakeHelper()).check_preconditions({"ip": "203.0.113.9", "ttl_s": 0}))
    assert check.ok is False and "thời hạn" in check.detail


def test_verification_reads_the_kernel_not_the_apply_message():
    """Mục 3.4: command exit code 0 không đồng nghĩa containment đã thành công."""
    adapter = _adapter(FakeHelper(), ips=())   # helper nói OK, kernel nói không có
    applied = run(adapter.apply({"ip": "203.0.113.9"}, "k"))
    assert applied.ok is True
    verified = run(adapter.verify({"ip": "203.0.113.9"}, applied))
    assert verified.verified is False
    assert "không có trong set" in verified.reason


def test_verification_passes_when_the_kernel_agrees():
    adapter = _adapter(FakeHelper(), ips=("203.0.113.9",))
    applied = run(adapter.apply({"ip": "203.0.113.9"}, "k"))
    verified = run(adapter.verify({"ip": "203.0.113.9"}, applied))
    assert verified.verified is True
    assert verified.observed["target"] == "203.0.113.9"


def test_verification_without_a_way_to_read_the_system_fails_closed():
    """`verified=True` với `observed` rỗng là một lời nói dối."""
    adapter = TemporaryBlockAdapter(FakeHelper(), nft_reader=None)
    verified = run(adapter.verify({"ip": "1.2.3.4"}, ApplyResult(True)))
    assert verified.verified is False
    assert verified.observed == {}


def test_rolling_back_something_already_gone_is_success():
    """Đích đến là 'địa chỉ này không bị chặn nữa', và nó đã đúng."""
    helper = FakeHelper({"unblock_ip": {"ok": False, "message": "No such file or directory"}})
    result = run(_adapter(helper).rollback({"ip": "1.2.3.4"}, ApplyResult(True)))
    assert result.ok is True


# --- executor ---


def _executor(jobs, adapter, on_critical=None):
    return ResponseExecutorV2(jobs, {"block_ip": adapter}, on_critical=on_critical)


def _approved(jobs, ttl_s=300):
    job, _ = jobs.create(idempotency_key="k", action="block_ip",
                         target={"ip": "203.0.113.9"}, ttl_s=ttl_s)
    jobs.transition(job.job_id, JobState.APPROVED, actor="khoa")
    return job


def test_a_happy_path_ends_verified(jobs):
    job = _approved(jobs)
    result = run(_executor(jobs, _adapter(FakeHelper(), ips=("203.0.113.9",))).run(job.job_id))
    assert result.state == JobState.VERIFIED
    assert [h["to_state"] for h in jobs.transitions(job.job_id)] == [
        JobState.PROPOSED, JobState.APPROVED, JobState.APPLYING,
        JobState.APPLIED, JobState.VERIFYING, JobState.VERIFIED]


def test_verification_failure_rolls_back_a_reversible_action(jobs):
    """Gate: verification failure tự rollback action reversible theo policy."""
    helper = FakeHelper()
    job = _approved(jobs)
    result = run(_executor(jobs, _adapter(helper, ips=())).run(job.job_id))
    assert result.state == JobState.ROLLED_BACK
    assert ("unblock_ip", {"ip": "203.0.113.9"}) in helper.calls
    states = [h["to_state"] for h in jobs.transitions(job.job_id)]
    assert JobState.VERIFY_FAILED in states and JobState.ROLLING_BACK in states


def test_the_verification_evidence_is_persisted(jobs):
    """Gate: UI hiển thị evidence hậu kiểm — nên nó phải được lưu."""
    job = _approved(jobs)
    run(_executor(jobs, _adapter(FakeHelper(), ips=("203.0.113.9",))).run(job.job_id))
    records = jobs.verifications(job.job_id)
    assert records and records[-1]["verified"] is True
    assert records[-1]["observed"], "kiểm chứng không lưu lại bằng chứng nào"


def test_failing_preconditions_never_touches_the_system(jobs):
    helper = FakeHelper()
    job, _ = jobs.create(idempotency_key="k", action="block_ip",
                         target={"ip": "192.168.1.1"}, ttl_s=300)
    jobs.transition(job.job_id, JobState.APPROVED, actor="khoa")
    adapter = _adapter(helper, gateway="192.168.1.1")
    result = run(_executor(jobs, adapter).run(job.job_id))
    assert result.state in {JobState.APPLY_FAILED, JobState.ROLLED_BACK}
    assert not any(call[0] == "block_ip" for call in helper.calls), \
        "đã chạm vào hệ thống dù tiền điều kiện không đạt"


def test_a_failed_rollback_raises_a_critical_alarm(jobs):
    """Gate: rollback failure tạo critical system incident và notify NGOÀI agent."""
    alarms = []
    helper = FakeHelper({"unblock_ip": {"ok": False, "message": "nft bận"}})
    job = _approved(jobs)
    executor = _executor(jobs, _adapter(helper, ips=()), on_critical=lambda j, d: alarms.append(d))
    result = run(executor.run(job.job_id))
    assert result.state == JobState.ROLLBACK_FAILED
    assert alarms and "nft bận" in alarms[0]


def test_a_broken_alarm_never_hides_the_failure(jobs):
    def explode(job, detail):
        raise RuntimeError("kênh báo động hỏng")

    helper = FakeHelper({"unblock_ip": {"ok": False, "message": "nft bận"}})
    job = _approved(jobs)
    result = run(_executor(jobs, _adapter(helper, ips=()), on_critical=explode).run(job.job_id))
    assert result.state == JobState.ROLLBACK_FAILED


def test_running_an_unapproved_job_is_refused(jobs):
    job, _ = jobs.create(idempotency_key="k", action="block_ip", target={"ip": "1.2.3.4"})
    with pytest.raises(TransitionError, match="chưa được duyệt"):
        run(_executor(jobs, _adapter(FakeHelper())).run(job.job_id))


def test_approving_requires_naming_who_approved(jobs):
    job, _ = jobs.create(idempotency_key="k", action="block_ip", target={})
    with pytest.raises(ValueError, match="ai đã duyệt"):
        run(_executor(jobs, _adapter(FakeHelper())).approve(job.job_id, actor=""))


# --- crash ở mọi trạng thái ---


@pytest.mark.parametrize("crash_state", sorted(UNFINISHED))
def test_recovery_handles_a_crash_in_any_unfinished_state(jobs, crash_state):
    """Gate: kill agent tại mọi state vẫn recover hoặc rollback đúng."""
    job, _ = jobs.create(idempotency_key=f"k-{crash_state}", action="block_ip",
                         target={"ip": "203.0.113.9"}, ttl_s=300)
    path = {
        JobState.APPLYING: [JobState.APPROVED, JobState.APPLYING],
        JobState.APPLIED: [JobState.APPROVED, JobState.APPLYING, JobState.APPLIED],
        JobState.VERIFYING: [JobState.APPROVED, JobState.APPLYING, JobState.APPLIED,
                             JobState.VERIFYING],
        JobState.ROLLING_BACK: [JobState.APPROVED, JobState.APPLYING,
                                JobState.ROLLING_BACK],
    }[crash_state]
    for state in path:
        jobs.transition(job.job_id, state, actor="test")

    helper = FakeHelper()
    handled = run(_executor(jobs, _adapter(helper, ips=())).recover())
    assert handled and handled[0]["outcome"] == JobState.ROLLED_BACK
    assert jobs.get(job.job_id).state == JobState.ROLLED_BACK
    assert ("unblock_ip", {"ip": "203.0.113.9"}) in helper.calls


def test_recovery_leaves_irreversible_work_for_a_human(jobs):
    """Tự động 'sửa' một thứ không đảo ngược được là cách làm hỏng thêm."""
    class Irreversible:
        action = "stop_process"
        reversible = False
        human_only = True

        async def preview(self, plan): return Impact("")
        async def check_preconditions(self, plan): return CheckResult(True)
        async def apply(self, plan, key): return ApplyResult(True)
        async def verify(self, plan, applied): return VerificationResult(True)
        async def rollback(self, plan, applied): return RollbackResult(False, "không thể")

    job, _ = jobs.create(idempotency_key="k", action="stop_process", target={"pid": 9})
    for state in (JobState.APPROVED, JobState.APPLYING, JobState.APPLIED):
        jobs.transition(job.job_id, state, actor="test")
    executor = ResponseExecutorV2(jobs, {"stop_process": Irreversible()})
    handled = run(executor.recover())
    assert handled[0]["outcome"] == "left_for_human"
    assert jobs.get(job.job_id).state == JobState.APPLIED


def test_recovery_does_nothing_to_finished_jobs(jobs):
    job = _approved(jobs)
    run(_executor(jobs, _adapter(FakeHelper(), ips=("203.0.113.9",))).run(job.job_id))
    assert run(_executor(jobs, _adapter(FakeHelper())).recover()) == []


# --- TTL ---


def test_the_ttl_clock_starts_when_the_action_is_applied(jobs, store):
    """Một job nằm chờ người duyệt ba tiếng không được coi là hết hạn ngay khi
    vừa áp."""
    clock = [1000.0]
    timed = ResponseJobStore(store.conn, clock=lambda: clock[0])
    job, _ = timed.create(idempotency_key="k", action="block_ip",
                          target={"ip": "203.0.113.9"}, ttl_s=300)
    clock[0] += 10_000          # nằm chờ rất lâu
    timed.transition(job.job_id, JobState.APPROVED, actor="khoa")
    timed.transition(job.job_id, JobState.APPLYING, actor="s")
    applied = timed.transition(job.job_id, JobState.APPLIED, actor="s")
    assert applied.expires_ts == clock[0] + 300


def test_an_expired_block_is_rolled_back(jobs, store):
    clock = [1000.0]
    timed = ResponseJobStore(store.conn, clock=lambda: clock[0])
    job, _ = timed.create(idempotency_key="k", action="block_ip",
                          target={"ip": "203.0.113.9"}, ttl_s=60)
    for state in (JobState.APPROVED, JobState.APPLYING, JobState.APPLIED):
        timed.transition(job.job_id, state, actor="s")
    assert timed.expired() == []
    clock[0] += 61
    helper = FakeHelper()
    result = run(ResponseExecutorV2(timed, {"block_ip": _adapter(helper)}).expire_due())
    assert result and result[0]["outcome"] == JobState.ROLLED_BACK
    assert ("unblock_ip", {"ip": "203.0.113.9"}) in helper.calls


def test_a_rolled_back_job_has_no_expiry_left(jobs):
    job = _approved(jobs, ttl_s=60)
    run(_executor(jobs, _adapter(FakeHelper(), ips=())).run(job.job_id))
    assert jobs.get(job.job_id).expires_ts == 0.0


# --- ranh giới adapter ---


def test_every_adapter_declares_the_full_contract():
    """Không thêm action mới nếu thiếu verify() và rollback()."""
    import shield.response.adapters.temporary_block as module

    for name in dir(module):
        obj = getattr(module, name)
        if not isinstance(obj, type) or not name.endswith("Adapter"):
            continue
        for method in ("preview", "check_preconditions", "apply", "verify", "rollback"):
            assert callable(getattr(obj, method, None)), f"{name} thiếu {method}"
        assert isinstance(getattr(obj, "reversible", None), bool), name
        assert isinstance(getattr(obj, "human_only", None), bool), name


def test_no_adapter_imports_the_ai_package():
    """AI không được có đường tới lớp hành động — và ngược lại cũng vậy."""
    for path in sorted((ROOT / "shield/response").glob("**/*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = ""
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
            elif isinstance(node, ast.Import):
                module = node.names[0].name
            assert not module.startswith("shield.ai"), f"{path.name} -> {module}"


# --- hai ngôn ngữ ---


def test_adapter_reasons_carry_a_translation_key():
    """Agent chạy ở tiến trình khác và KHÔNG BIẾT người đang nhìn màn hình
    chọn ngôn ngữ nào — chỉ giao diện biết.

    Đây là lần thứ BA cùng một lỗi trong dự án (thông báo lỗi xuất log, kết quả
    phân tích, lý do kiểm chứng), nên nó được đưa vào KIỂU dữ liệu thay vì sửa
    từng chỗ.
    """
    from shield.response.adapters.temporary_block import protected_reason_key

    check = run(_adapter(FakeHelper(), gateway="192.168.1.1").check_preconditions(
        {"ip": "192.168.1.1", "ttl_s": 300}))
    assert check.reason_key
    key, fallback = protected_reason_key("192.168.1.1", gateway="192.168.1.1")
    assert key and fallback


def test_verification_reasons_carry_a_translation_key():
    adapter = _adapter(FakeHelper(), ips=())
    verified = run(adapter.verify({"ip": "203.0.113.9"}, ApplyResult(True)))
    assert verified.reason_key == "response.verify_err_absent"
    assert verified.reason_params == {"ip": "203.0.113.9"}


def test_every_adapter_reason_key_exists_in_both_languages():
    from shield.ui.i18n import STRINGS

    keys = set()
    adapter = _adapter(FakeHelper(), gateway="192.168.1.1", resolvers=("8.8.8.8",),
                       management="192.168.1.20")
    for target, ttl in (("192.168.1.1", 300), ("8.8.8.8", 300), ("192.168.1.20", 300),
                        ("127.0.0.1", 300), ("224.0.0.1", 300), ("khong-hop-le", 300),
                        ("203.0.113.9", 0)):
        check = run(adapter.check_preconditions({"ip": target, "ttl_s": ttl}))
        if check.reason_key:
            keys.add(check.reason_key)
    keys.add(run(_adapter(FakeHelper(), ips=()).verify(
        {"ip": "1.2.3.4"}, ApplyResult(True))).reason_key)
    keys.add(run(TemporaryBlockAdapter(FakeHelper(), nft_reader=None).verify(
        {"ip": "1.2.3.4"}, ApplyResult(True))).reason_key)

    assert len(keys) >= 6
    for key in keys:
        assert key in STRINGS, f"khoá {key} chưa có bản dịch"
        vietnamese, english = STRINGS[key]
        assert vietnamese.strip() and english.strip() and vietnamese != english, key


def test_the_verification_record_keeps_the_translation_key(jobs):
    """Một bản ghi hậu kiểm đọc lại sáu tháng sau vẫn phải hiển thị được bằng
    ngôn ngữ người đọc chọn LÚC ĐÓ, không phải ngôn ngữ agent dùng lúc ghi."""
    job = _approved(jobs)
    run(_executor(jobs, _adapter(FakeHelper(), ips=())).run(job.job_id))
    record = jobs.verifications(job.job_id)[-1]
    assert record["reason_key"] == "response.verify_err_absent"
    assert record["reason_params"] == {"ip": "203.0.113.9"}
    assert "_reason_key" not in record["observed"], "khoá nội bộ rò vào bằng chứng"


def test_every_job_state_is_translatable():
    """"APPLY_FAILED" không nói gì với người không đọc mã nguồn."""
    from shield.ui.i18n import STRINGS

    for state in JobState.ALL:
        key = f"response.state.{state}"
        assert key in STRINGS, state
        vietnamese, english = STRINGS[key]
        assert vietnamese.strip() and english.strip() and vietnamese != english, state


# --- công tắc dừng phản ứng ---


def test_the_response_kill_switch_stops_new_work(jobs, monkeypatch):
    """Chặn TRƯỚC khi chạm vào hệ thống."""
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

    helper = FakeHelper()
    job = _approved(jobs)
    monkeypatch.setenv(RESPONSE_KILL_SWITCH_ENV, "1")
    result = run(_executor(jobs, _adapter(helper, ips=())).run(job.job_id))
    assert result.state == JobState.APPROVED, "job vẫn chạy dù công tắc đang bật"
    assert helper.calls == [], "đã chạm vào hệ thống dù công tắc đang bật"


def test_approved_work_is_kept_not_cancelled(jobs, monkeypatch):
    """Huỷ nghĩa là người vận hành phải duyệt lại từ đầu sau sự cố."""
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

    job = _approved(jobs)
    monkeypatch.setenv(RESPONSE_KILL_SWITCH_ENV, "1")
    run(_executor(jobs, _adapter(FakeHelper(), ips=())).run(job.job_id))
    monkeypatch.delenv(RESPONSE_KILL_SWITCH_ENV)
    result = run(_executor(jobs, _adapter(FakeHelper(), ips=("203.0.113.9",))).run(job.job_id))
    assert result.state == JobState.VERIFIED


def test_the_kill_switch_never_blocks_a_rollback(jobs, monkeypatch):
    """Một công tắc an toàn mà cũng chặn đường GỠ sẽ đóng băng mọi luật firewall
    đang áp, và người bấm nó để dừng thiệt hại lại là người gây ra thiệt hại
    lớn hơn. Dừng làm thêm, không dừng dọn dẹp.
    """
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

    helper = FakeHelper()
    job = _approved(jobs)
    run(_executor(jobs, _adapter(helper, ips=("203.0.113.9",))).run(job.job_id))
    assert jobs.get(job.job_id).state == JobState.VERIFIED

    monkeypatch.setenv(RESPONSE_KILL_SWITCH_ENV, "1")
    result = run(_executor(jobs, _adapter(helper, ips=())).rollback(
        job.job_id, actor="operator", reason="dừng khẩn"))
    assert result.state == JobState.ROLLED_BACK
    assert ("unblock_ip", {"ip": "203.0.113.9"}) in helper.calls


def test_the_kill_switch_never_blocks_crash_recovery(jobs, monkeypatch):
    """Phục hồi sau crash cũng là dọn dẹp, không phải làm thêm."""
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

    job, _ = jobs.create(idempotency_key="k", action="block_ip",
                         target={"ip": "203.0.113.9"}, ttl_s=300)
    for state in (JobState.APPROVED, JobState.APPLYING, JobState.APPLIED):
        jobs.transition(job.job_id, state, actor="test")
    monkeypatch.setenv(RESPONSE_KILL_SWITCH_ENV, "1")
    handled = run(_executor(jobs, _adapter(FakeHelper(), ips=())).recover())
    assert handled and handled[0]["outcome"] == JobState.ROLLED_BACK


def test_approving_while_stopped_is_denied_with_a_reason(jobs, monkeypatch):
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

    job, _ = jobs.create(idempotency_key="k", action="block_ip", target={"ip": "1.2.3.4"})
    monkeypatch.setenv(RESPONSE_KILL_SWITCH_ENV, "1")
    result = run(_executor(jobs, _adapter(FakeHelper())).approve(job.job_id, actor="khoa"))
    assert result.state == JobState.DENIED
    assert "công tắc" in jobs.transitions(job.job_id)[-1]["detail"]


def test_the_switch_is_read_fresh_every_time(monkeypatch):
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV, response_automation_killed

    monkeypatch.delenv(RESPONSE_KILL_SWITCH_ENV, raising=False)
    assert response_automation_killed() is False
    monkeypatch.setenv(RESPONSE_KILL_SWITCH_ENV, "true")
    assert response_automation_killed() is True
    monkeypatch.setenv(RESPONSE_KILL_SWITCH_ENV, "no")
    assert response_automation_killed() is False


def test_the_switch_survives_a_restart():
    source = (ROOT / "shield/agent/__main__.py").read_text(encoding="utf-8")
    assert 'store.get_baseline("response_kill_switch")' in source
    assert 'add_audit_log("set_response_kill_switch"' in source


def test_both_kill_switches_are_independent():
    """Tắt AI không được làm ngừng phản ứng, và ngược lại: chúng dùng cho hai
    tình huống khác nhau và trộn vào một công tắc sẽ khiến người ta không dám
    bấm cái nào."""
    from shield.ai.capability import KILL_SWITCH_ENV
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

    assert KILL_SWITCH_ENV != RESPONSE_KILL_SWITCH_ENV


def test_both_kill_switches_are_translatable():
    from shield.ui.i18n import STRINGS

    for key in ("ai.kill_switch", "ai.kill_switch_hint", "response.kill_switch",
                "response.kill_switch_hint", "response.kill_switch_on",
                "response.kill_switch_off"):
        assert key in STRINGS, key
        vietnamese, english = STRINGS[key]
        assert vietnamese.strip() and english.strip() and vietnamese != english, key
