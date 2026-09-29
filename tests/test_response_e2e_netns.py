"""Response end-to-end với nftables THẬT: duyệt -> áp -> kiểm chứng -> gỡ.

Chạy đúng executor mà agent dựng (`build_response_executor`), đúng privileged
helper (tiến trình riêng, Unix socket), đúng lệnh nft. Chỉ chạy khi có root VÀ
cờ có chủ đích, và chỉ nên chạy trong namespace mạng dùng một lần (container
hoặc VM) — nó sửa ruleset nftables của namespace đang chạy:

    docker run --rm --privileged -e SHIELD_NETNS_TESTS=1 ... \
        python3 -m pytest tests/test_response_e2e_netns.py

Trước đây "Response actions beyond block_ip have had limited real-world
exercise" là một giới hạn được ghi trong README mà không có bài test nào chạy
thật đường apply/verify/rollback.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="chỉ Linux"),
    pytest.mark.skipif(os.geteuid() != 0, reason="cần root để sửa nftables"),
    pytest.mark.skipif(os.environ.get("SHIELD_NETNS_TESTS") != "1",
                       reason="đặt SHIELD_NETNS_TESTS=1 để chạy có chủ đích"),
]

ROOT = Path(__file__).resolve().parent.parent
TARGET = "198.51.100.23"          # RFC 5737, không bao giờ là máy thật


def _nft_has(ip: str) -> bool:
    out = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True).stdout
    return ip in out


class Ipc:
    async def broadcast(self, *_args):
        pass


@pytest.fixture
def helper():
    with tempfile.TemporaryDirectory() as tmp:
        sock = Path(tmp) / "helper.sock"
        env = dict(os.environ, SHIELD_HELPER_SOCK=str(sock), SHIELD_AGENT_UID="0", PYTHONPATH=str(ROOT))
        proc = subprocess.Popen([sys.executable, "-m", "shield.privileged"], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            if sock.exists() or proc.poll() is not None:
                break
            time.sleep(0.1)
        assert sock.exists(), f"privileged helper không lên: {proc.stderr.read() if proc.poll() else ''}"
        try:
            yield sock, Path(tmp)
        finally:
            proc.terminate()
            proc.wait(timeout=10)


async def _executor(sock: Path, db: Path):
    from shield.agent.__main__ import build_response_executor
    from shield.agent.store import Store
    from shield.privileged.client import PrivilegedClient

    store = Store(db)
    return store, await build_response_executor(store, PrivilegedClient(sock), Ipc(), None)


def _job(executor, action: str, target: dict, key: str):
    job, _new = executor.jobs.create(idempotency_key=key, action=action, target=target, ttl_s=600)
    return job


@pytest.mark.parametrize("action", ["block_ip", "rate_limit_ip"])
def test_apply_verify_then_rollback_against_real_nftables(helper, action):
    sock, tmp = helper

    async def scenario():
        store, executor = await _executor(sock, tmp / "s.db")
        job = _job(executor, action, {"ip": TARGET}, f"e2e-{action}")
        await executor.approve(job.job_id, actor="uid=0:e2e")
        done = await executor.run(job.job_id)
        applied = _nft_has(TARGET)
        verifications = executor.jobs.verifications(job.job_id)
        rolled = await executor.rollback(job.job_id, actor="uid=0:e2e", reason="test cleanup")
        return done.state, applied, verifications, rolled.state, _nft_has(TARGET), \
            [t["to_state"] for t in executor.jobs.transitions(job.job_id)]

    state, applied, verifications, rolled_state, still_there, history = asyncio.run(scenario())
    assert state == "VERIFIED", history
    assert applied, "nftables không có địa chỉ dù job báo VERIFIED"
    assert verifications and verifications[-1]["verified"] in (1, True)
    assert rolled_state == "ROLLED_BACK", history
    assert not still_there, "gỡ xong mà địa chỉ vẫn còn trong ruleset"


def test_a_protected_target_is_refused_before_touching_the_system(helper):
    sock, tmp = helper

    async def scenario():
        store, executor = await _executor(sock, tmp / "s.db")
        job = _job(executor, "block_ip", {"ip": "127.0.0.1"}, "e2e-protected")
        await executor.approve(job.job_id, actor="uid=0:e2e")
        state = (await executor.run(job.job_id)).state
        return state, [t["to_state"] for t in executor.jobs.transitions(job.job_id)]

    state, history = asyncio.run(scenario())
    assert state == "APPLY_FAILED", history
    # Bị từ chối ở tiền điều kiện: chưa bao giờ áp, nên cũng không có gì để gỡ.
    assert "APPLIED" not in history and "ROLLING_BACK" not in history, history


def test_a_failed_verification_rolls_the_change_back(helper):
    """Kiểm chứng hỏng = không biết hệ thống ở đâu -> phải quay về trạng thái đã biết."""
    sock, tmp = helper

    async def scenario():
        store, executor = await _executor(sock, tmp / "s.db")

        async def blind_reader() -> str:
            return ""

        executor.adapters["block_ip"].nft_reader = blind_reader
        job = _job(executor, "block_ip", {"ip": TARGET}, "e2e-verify-fail")
        await executor.approve(job.job_id, actor="uid=0:e2e")
        done = await executor.run(job.job_id)
        return done.state, _nft_has(TARGET), [t["to_state"] for t in executor.jobs.transitions(job.job_id)]

    state, still_there, history = asyncio.run(scenario())
    assert "VERIFY_FAILED" in history, history
    assert state == "ROLLED_BACK", history
    assert not still_there, "rollback tự động không gỡ được luật"


def test_evidence_of_the_run_is_written(helper):
    """Ghi ruleset thật vào log để người đọc bằng chứng thấy tận mắt."""
    out = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    print("NFT_RULESET_AFTER_TESTS", json.dumps(json.loads(out.stdout or "{}"))[:4000])
    assert out.returncode == 0
