import asyncio
from pathlib import Path

from shield.security.response import Quarantine, ResponseExecutor, process_start_ticks, stop_process


def fake_proc(tmp_path: Path, pid=42, ticks="123"):
    root = tmp_path / "proc"
    path = root / str(pid)
    path.mkdir(parents=True)
    fields = ["S"] + ["0"] * 18 + [ticks] + ["0"] * 5
    (path / "stat").write_text(f"{pid} (test worker) " + " ".join(fields))
    return root


def test_stop_process_checks_pid_identity_and_dry_runs(tmp_path):
    root = fake_proc(tmp_path)
    assert process_start_ticks(42, root) == "123"
    assert stop_process(42, "wrong", proc_root=root).ok is False
    result = stop_process(42, "123", proc_root=root)
    assert result.ok and "dry-run" in result.message


def test_stop_process_protects_init(tmp_path):
    assert process_start_ticks(1, tmp_path) is None


def test_quarantine_and_restore_roundtrip(tmp_path):
    original = tmp_path / "payload.bin"
    original.write_bytes(b"suspicious")
    quarantine = Quarantine(tmp_path / "quarantine")
    preview = quarantine.quarantine(original)
    assert preview.ok and original.exists()
    result = quarantine.quarantine(original, dry_run=False)
    assert result.ok and not original.exists() and result.rollback_id
    restore_preview = quarantine.restore(result.rollback_id)
    assert restore_preview.ok and not original.exists()
    restored = quarantine.restore(result.rollback_id, dry_run=False)
    assert restored.ok and original.read_bytes() == b"suspicious"


def test_quarantine_rejects_symlink_and_large_file(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"1234")
    link = tmp_path / "link"
    link.symlink_to(target)
    quarantine = Quarantine(tmp_path / "q", max_bytes=3)
    assert not quarantine.quarantine(link).ok
    assert not quarantine.quarantine(target).ok


def test_restore_refuses_to_overwrite_existing_destination(tmp_path):
    original = tmp_path / "payload"
    original.write_text("old")
    quarantine = Quarantine(tmp_path / "q")
    result = quarantine.quarantine(original, dry_run=False)
    original.write_text("new")
    refused = quarantine.restore(result.rollback_id, dry_run=False)
    assert not refused.ok
    assert original.read_text() == "new"


def test_executor_token_is_single_use_and_bound_to_params(tmp_path, monkeypatch):
    async def direct(fn, *args, **kwargs):
        return fn(*args, **kwargs)
    # Managed CI forbids the eventfd used by asyncio's thread pool; the
    # synchronous quarantine primitive is tested separately above.
    monkeypatch.setattr(asyncio, "to_thread", direct)
    async def scenario():
        original = tmp_path / "payload"
        original.write_text("x")
        executor = ResponseExecutor(Quarantine(tmp_path / "q"))
        token, preview = await executor.preview("quarantine_file", {"path": str(original)})
        assert token and preview.ok
        mismatch = await executor.execute(token, "quarantine_file", {"path": str(tmp_path / "other")})
        assert not mismatch.ok
        second = await executor.execute(token, "quarantine_file", {"path": str(original)})
        assert not second.ok
    asyncio.run(scenario())


def test_executor_successful_two_step_execution(tmp_path, monkeypatch):
    async def direct(fn, *args, **kwargs):
        return fn(*args, **kwargs)
    monkeypatch.setattr(asyncio, "to_thread", direct)
    async def scenario():
        original = tmp_path / "payload"
        original.write_text("x")
        executor = ResponseExecutor(Quarantine(tmp_path / "q"))
        params = {"path": str(original)}
        token, _ = await executor.preview("quarantine_file", params)
        result = await executor.execute(token, "quarantine_file", params)
        assert result.ok and not original.exists()
    asyncio.run(scenario())


def test_executor_token_is_bound_to_client_identity(tmp_path, monkeypatch):
    async def direct(fn, *args, **kwargs):
        return fn(*args, **kwargs)
    monkeypatch.setattr(asyncio, "to_thread", direct)
    async def scenario():
        original = tmp_path / "payload"
        original.write_text("x")
        executor = ResponseExecutor(Quarantine(tmp_path / "q"))
        params = {"path": str(original)}
        token, _ = await executor.preview("quarantine_file", params, owner="uid=1000:pid=10")
        result = await executor.execute(token, "quarantine_file", params, owner="uid=1000:pid=11")
        assert not result.ok
        assert original.exists()
    asyncio.run(scenario())


def test_stop_execution_routes_through_privileged_helper(tmp_path, monkeypatch):
    class FakeHelper:
        def __init__(self): self.calls = []
        async def call(self, action, params):
            self.calls.append((action, params))
            return {"ok": True, "message": "SIGTERM sent"}

    async def direct(fn, *args, **kwargs):
        # Preview still validates PID identity locally; provide a fake /proc via
        # patching the primitive's result for this boundary test.
        if fn is stop_process:
            from shield.security.response import ResponseResult
            return ResponseResult(True, "stop_process", "pid:42", "dry-run")
        return fn(*args, **kwargs)
    monkeypatch.setattr(asyncio, "to_thread", direct)

    async def scenario():
        helper = FakeHelper()
        executor = ResponseExecutor(Quarantine(tmp_path / "q"), privileged_client=helper)
        params = {"pid": 42, "start_ticks": "123"}
        token, preview = await executor.preview("stop_process", params, owner="client")
        assert preview.ok
        result = await executor.execute(token, "stop_process", params, owner="client")
        assert result.ok
        assert helper.calls == [("stop_process", params)]
    asyncio.run(scenario())
