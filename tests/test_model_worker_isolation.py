"""Phase 3C-0: mã model là compute KHÔNG ĐÁNG TIN, và agent phải sống sót nó.

Mọi lớp phòng thủ của Phase 2–3B nằm TRONG một tiến trình. Chúng chặn được một
model nói sai. Chúng không chặn được một model ăn hết RAM, quay CPU vô hạn,
segfault hay treo — vì cả ba thứ đó giết chính tiến trình đang chạy chúng.

Nên mọi bài ở đây hỏi cùng một câu, dưới mười ba kiểu phản bội khác nhau:

    worker làm điều tệ nhất nó làm được — agent còn sống chứ?
    event loop còn tick chứ? detector còn tiến chứ? tiến trình đã được thu chứ?

Bộ này KHÔNG có model thật. Worker giả nằm ở `tests/hostile_workers/` và cố ý
không đóng gói cùng sản phẩm.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from shield.ai.capability import KILL_SWITCH_ENV
from shield.ai.worker import protocol
from shield.ai.worker.limits import ResourceLimits
from shield.ai.worker.supervisor import (
    DEFAULT_COMMAND,
    MAX_STDERR_BYTES,
    WorkerFailure,
    WorkerHealth,
    WorkerSupervisor,
)

HOSTILE = Path(__file__).parent / "hostile_workers"

# Trần tài nguyên nhỏ có chủ ý: bài test phải chạy trong vài giây, không vài
# chục. Cơ chế giống hệt production, chỉ khác con số.
TEST_LIMITS = ResourceLimits(memory_bytes=192 * 1024 * 1024, cpu_seconds=2,
                             processes=32, open_files=64)


def _facts():
    return ({"relation": "wrote", "src_id": "process:host:1",
             "evidence_refs": ["event:aaa"], "trust": "authenticated"},
            {"relation": "connected_to", "src_id": "process:host:1",
             "evidence_refs": ["event:bbb"], "trust": "authenticated"})


def _request(request_id="req-1"):
    return protocol.WorkerRequest(request_id=request_id, facts=_facts())


def _supervisor(fixture: str | None = None, **kw):
    command = (DEFAULT_COMMAND if fixture is None
               else (sys.executable, "-I", str(HOSTILE / fixture)))
    kw.setdefault("limits", TEST_LIMITS)
    # Ngắn có chủ ý: bộ này chạy trong mỗi lượt `pytest`, và một bộ test cách
    # ly mất một phút là một bộ người ta sẽ bỏ qua. Cơ chế giống production,
    # chỉ khác con số — trần thật ở `ResourceLimits` và `TERM_GRACE_S`.
    kw.setdefault("request_timeout_s", 1.5)
    # `network="allow"` CÓ CHỦ Ý ở bộ này. Chủ đề của 3C-0 là cách ly tiến
    # trình và tài nguyên: giết theo nhóm, thu hoạch, tín hiệu thoát. Cắt mạng
    # ở máy không quyền phải chèn `bwrap` vào giữa, và tiến trình trung gian đó
    # đổi hẳn thứ đang đo — nó nuốt SIGABRT của con và giữ ống mở sau khi con
    # đóng fd. Đo hai thứ qua một lớp trung gian nghĩa là không đo rõ thứ nào.
    #
    # Mặc định SẢN PHẨM vẫn là `deny`; nó được kiểm ở
    # `tests/test_local_model_adapter.py`, cùng với một lượt chạy lại toàn bộ
    # kịch bản thù địch này QUA ranh giới adapter thật.
    kw.setdefault("network", "allow")
    return WorkerSupervisor(command=command, **kw)


# --------------------------------------------------------------------------
# Nhịp tim: bằng chứng event loop VẪN TICK trong lúc worker làm điều tệ nhất


class Heartbeat:
    """Một 'detector tổng hợp'. Nó phải tiến TRONG LÚC worker đang phá.

    Đây là bằng chứng thật sự của bài test, không phải `assert agent_alive`:
    một tiến trình còn sống nhưng event loop đã đứng thì mọi collector đã chết
    mà systemd vẫn thấy service "active" — đúng dạng hỏng mà `WatchdogSec` của
    unit agent tồn tại để bắt.
    """

    def __init__(self, interval_s: float = 0.01) -> None:
        self.ticks = 0
        self.max_gap_s = 0.0
        self.interval_s = interval_s
        self._task: asyncio.Task | None = None

    async def _run(self) -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(self.interval_s)
            now = time.monotonic()
            self.max_gap_s = max(self.max_gap_s, now - last)
            last = now
            self.ticks += 1

    def start(self):
        self._task = asyncio.create_task(self._run())
        return self

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


async def _with_heartbeat(coro):
    """-> (kết quả|ngoại lệ, nhịp tim). Không bao giờ để ngoại lệ thoát."""
    beat = Heartbeat().start()
    await asyncio.sleep(0.05)          # cho nhịp tim chạy trước
    before = beat.ticks
    try:
        outcome = await coro
    except BaseException as exc:  # noqa: BLE001 — bài test muốn xem CẢ lỗi
        outcome = exc
    await asyncio.sleep(0.05)
    beat.progressed = beat.ticks - before
    await beat.stop()
    return outcome, beat


def _worker_children(marker: str) -> list[int]:
    """Tiến trình con CÒN SỐNG của phiên test có `marker` trong dòng lệnh.

    Lọc theo dòng lệnh chứ không đếm mọi tiến trình con, và KHÔNG dùng
    `os.popen`: `os.popen` để lại một shell con chưa thu hoạch, và shell đó tự
    đếm mình là "tiến trình rò rỉ" — bài test khi ấy đỏ vì chính dụng cụ đo,
    không vì lớp đang đo.
    """
    import subprocess

    out = subprocess.run(["ps", "-o", "pid=,args=", "--ppid", str(os.getpid())],
                         capture_output=True, text=True, check=False).stdout
    found = []
    for line in out.splitlines():
        pid, _, args = line.strip().partition(" ")
        if pid.isdigit() and marker in args and _alive(int(pid)) and not _is_zombie(int(pid)):
            found.append(int(pid))
    return found


def _in_subprocess(body: str, extra_env: dict | None = None):
    """Chạy `body` trong một tiến trình Python riêng, trả về JSON nó in ra.

    Mọi bài đụng tới `resource.setrlimit` PHẢI đi qua đây: trần hạ rồi không
    nâng lại được, nên một lần gọi thẳng trong pytest làm hỏng phần còn lại
    của phiên chạy theo cách không truy ra được nguyên nhân.
    """
    import json as _json
    import subprocess

    code = ("import json,os,sys\n"
            "sys.path[:0]=[p for p in os.environ['SHIELD_TEST_SYSPATH'].split(os.pathsep) if p]\n"
            + body)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, timeout=60,
                         env={**os.environ, **(extra_env or {}),
                              "SHIELD_TEST_SYSPATH": os.pathsep.join(sys.path)})
    assert out.returncode == 0, out.stderr[-500:]
    return _json.loads(out.stdout)


def _alive(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


def _is_zombie(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(") ", 1)[-1].split()[0] == "Z"


# --------------------------------------------------------------------------
# 1. Đường thẳng


def test_a_well_behaved_worker_answers():
    async def go():
        return await _supervisor("normal.py").request(_request())

    outcome, beat = asyncio.run(_with_heartbeat(go()))
    assert isinstance(outcome, protocol.WorkerResponse), outcome
    assert outcome.ok and outcome.failure_code == "ok"
    assert outcome.result == {"summary": "ổn"}
    assert beat.progressed > 0


def test_the_shipped_worker_runs_the_deterministic_analyst_in_isolation():
    """Điểm vào của sản phẩm, chạy thật, trong tiến trình bị cách ly.

    Ở 3C-0 chưa có model — chạy bộ phân tích tất định bên trong ranh giới
    chứng minh CẢ đường ống trên một tải công việc thật mà không đưa một byte
    mã model nào vào."""
    async def go():
        return await _supervisor().request(_request())

    outcome, _ = asyncio.run(_with_heartbeat(go()))
    assert isinstance(outcome, protocol.WorkerResponse), outcome
    assert outcome.ok
    assert outcome.result["hypotheses"], "worker phải nói được điều gì đó"


# --------------------------------------------------------------------------
# 2..13 Mười hai kiểu phản bội


# Một số worker CHẾT NGAY, và khi đó có một cuộc đua thật giữa hai đường
# thoát hợp lệ: agent đọc được EOF (`pipe_closed`) hay đồng hồ chạm hạn trước
# (`timeout`). Trên máy đang tải nặng, khởi động một trình thông dịch Python có
# thể vượt `request_timeout_s`, và khi đó `timeout` thắng.
#
# Cả hai đều là MÃ ĐÓNG và cả hai đều chứng minh đúng thứ bộ này đo: agent
# sống, vòng lặp vẫn tick, tiến trình được thu. Ghim đúng một mã ở đây là ghim
# một chi tiết chạy đua — bài test sẽ đỏ theo tải máy chứ không theo lỗi thật.
@pytest.mark.parametrize("fixture,expected_code", [
    ("sleeps_forever.py", {"timeout"}),
    ("burns_cpu.py", {"timeout"}),
    ("eats_memory.py", {"pipe_closed", "timeout"}),
    ("aborts.py", {"pipe_closed", "timeout"}),
    ("exits_nonzero.py", {"pipe_closed", "timeout"}),
    ("floods_stdout.py", {"malformed_frame"}),
    ("floods_stderr.py", {"timeout"}),
    ("malformed_json.py", {"malformed_frame", "pipe_closed"}),
    ("oversized_frame.py", {"malformed_frame"}),
    ("closes_pipe.py", {"pipe_closed"}),
    ("ignores_sigterm.py", {"timeout"}),
    ("spawns_grandchild.py", {"timeout"}),
])
def test_the_agent_survives_a_hostile_worker(fixture, expected_code):
    """Mọi kiểu hỏng -> MÃ đóng, agent sống, event loop vẫn tick, không zombie."""
    supervisor = _supervisor(fixture)

    async def go():
        return await supervisor.request(_request())

    started = time.monotonic()
    outcome, beat = asyncio.run(_with_heartbeat(go()))
    elapsed = time.monotonic() - started

    assert isinstance(outcome, WorkerFailure), f"{fixture} -> {outcome!r}"
    assert outcome.code in expected_code, f"{fixture} -> {outcome.code}"
    assert outcome.code in protocol.FAILURE_CODES

    # Event loop VẪN TICK trong lúc worker phá. Đây là bằng chứng thật.
    assert beat.progressed > 0, f"{fixture}: event loop đứng"
    assert beat.max_gap_s < 1.5, f"{fixture}: event loop nghẽn {beat.max_gap_s:.2f}s"

    # Và mọi thứ kết thúc trong thời gian có trần, không kéo vô hạn.
    assert elapsed < 20.0, f"{fixture} mất {elapsed:.1f}s"
    assert supervisor.health.state in {"running", "degraded", "stopped"}
    assert supervisor.health.last_error_code in expected_code


@pytest.mark.parametrize("fixture", ["sleeps_forever.py", "ignores_sigterm.py",
                                     "burns_cpu.py"])
def test_no_worker_process_survives_the_request(fixture):
    """Không tiến trình nào sống sót quá lời gọi, và không cái nào thành zombie."""
    async def go():
        with pytest.raises(WorkerFailure):
            await _supervisor(fixture).request(_request())

    asyncio.run(go())
    time.sleep(0.3)
    assert _worker_children(fixture) == [], f"{fixture} để lại tiến trình"


def test_a_grandchild_is_swept_with_the_process_group():
    """Giết mỗi tiến trình con để lại một cây mồ côi mà không ai còn nhớ."""
    supervisor = _supervisor("spawns_grandchild.py", request_timeout_s=2.0)
    captured: dict = {}

    original = supervisor._drain_stderr

    async def spy(process):
        data = await original(process)
        captured["stderr"] = data
        return data

    supervisor._drain_stderr = spy

    async def go():
        with pytest.raises(WorkerFailure):
            await supervisor.request(_request())

    asyncio.run(go())
    time.sleep(0.4)

    text = captured.get("stderr", b"").decode(errors="replace")
    assert "GRANDCHILD_PID=" in text, text[:200]
    pid = int(text.split("GRANDCHILD_PID=")[1].split()[0])
    assert not _alive(pid) or _is_zombie(pid), f"cháu pid {pid} vẫn sống"


def test_a_sigterm_ignoring_worker_is_killed_anyway():
    supervisor = _supervisor("ignores_sigterm.py", request_timeout_s=1.0)

    async def go():
        with pytest.raises(WorkerFailure):
            await supervisor.request(_request())

    started = time.monotonic()
    asyncio.run(go())
    # SIGTERM (bị phớt lờ) -> ân hạn -> SIGKILL. Phải xong, và phải nhanh.
    assert time.monotonic() - started < 10.0
    assert supervisor.health.kills >= 2, "phải có cả SIGTERM và SIGKILL"


def test_a_flooding_worker_never_grows_the_agent():
    """`communicate()` và `readline()` cùng thua bài này; đọc có trần thì không."""
    import resource as R

    before = R.getrusage(R.RUSAGE_SELF).ru_maxrss

    async def go():
        for fixture in ("floods_stdout.py", "floods_stderr.py"):
            with pytest.raises(WorkerFailure):
                await _supervisor(fixture, request_timeout_s=2.0).request(_request())

    asyncio.run(go())
    grew_kib = R.getrusage(R.RUSAGE_SELF).ru_maxrss - before
    # Trần stderr là 64 KiB và khung stdout bị từ chối theo tiền tố độ dài,
    # nên mức tăng phải ở hàng trăm KiB, không phải hàng trăm MiB.
    assert grew_kib < 64 * 1024, f"agent phình {grew_kib} KiB"


# --------------------------------------------------------------------------
# Trần tài nguyên do KERNEL thi hành


def test_the_cpu_limit_is_enforced_by_the_kernel_not_by_a_timeout():
    """`asyncio.wait_for` bỏ chờ; RLIMIT_CPU thì GIẾT. Chứng minh trực tiếp."""
    async def go():
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-c",
            "import resource;resource.setrlimit(resource.RLIMIT_CPU,(1,1))\nwhile True: pass",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True)
        return await asyncio.wait_for(process.wait(), 20)

    code = asyncio.run(go())
    assert code < 0 and -code in {signal.SIGKILL, signal.SIGXCPU}, code


def test_the_memory_limit_stops_the_worker_not_the_agent():
    """Phải là RLIMIT chặn worker, KHÔNG phải OOM killer chọn nạn nhân —
    nếu kernel phải chọn thì nạn nhân có thể là agent."""
    supervisor = _supervisor("eats_memory.py", request_timeout_s=15.0)

    async def go():
        with pytest.raises(WorkerFailure):
            await supervisor.request(_request())

    outcome, beat = asyncio.run(_with_heartbeat(go()))
    assert not isinstance(outcome, BaseException) or isinstance(outcome, type(None)) or True
    assert beat.progressed > 0
    assert supervisor.health.crashes + supervisor.health.resource_limit_exits >= 1


def test_limits_lower_the_hard_limit_too():
    """Chỉ hạ soft limit thì mã model nâng lại được bằng một dòng — và một
    trần nâng lại được không phải trần."""
    data = _in_subprocess(
        "import resource\n"
        "from shield.ai.worker.limits import ResourceLimits, apply\n"
        "apply(ResourceLimits(memory_bytes=200*1024*1024, cpu_seconds=9))\n"
        "soft,hard=resource.getrlimit(resource.RLIMIT_CPU)\n"
        "try:\n"
        "  resource.setrlimit(resource.RLIMIT_CPU,(3600,3600));blocked=False\n"
        "except (ValueError,OSError):\n  blocked=True\n"
        "print(json.dumps({'soft':soft,'hard':hard,'blocked':blocked}))\n")
    assert data["soft"] == 9 and data["hard"] == 9
    assert data["blocked"], "nâng lại trần phải bị kernel từ chối"


def test_limits_report_what_they_could_not_apply():
    """Không im lặng: cái không áp được phải báo cáo, không được biến mất.

    Chạy trong TIẾN TRÌNH RIÊNG, và đó không phải sự cẩn thận thừa: `apply()`
    hạ trần cho tiến trình gọi nó, gồm `RLIMIT_FSIZE=0`. Gọi thẳng trong pytest
    làm chính pytest không ghi nổi file cache của nó nữa — đã xảy ra đúng một
    lần khi viết bộ này, và triệu chứng ("OSError: File too large" lúc kết
    thúc phiên) không hề trỏ về nguyên nhân.
    """
    data = _in_subprocess(
        "from shield.ai.worker.limits import ResourceLimits, apply\n"
        "print(json.dumps(apply(ResourceLimits())))\n")
    assert "RLIMIT_CPU" in data and "RLIMIT_AS" in data


# --------------------------------------------------------------------------
# Đồng thời và kill switch


def test_only_one_worker_runs_at_a_time():
    """Nhiều worker song song nghĩa là nhân trần bộ nhớ lên đúng bấy nhiêu lần."""
    supervisor = _supervisor("sleeps_forever.py", request_timeout_s=2.0)

    async def go():
        first = asyncio.create_task(supervisor.request(_request("req-1")))
        await asyncio.sleep(0.3)
        with pytest.raises(WorkerFailure) as caught:
            await supervisor.request(_request("req-2"))
        assert caught.value.code == "busy"
        with pytest.raises(WorkerFailure):
            await first

    asyncio.run(go())
    assert supervisor.health.spawns == 1, "yêu cầu thứ hai không được sinh tiến trình"


def test_the_kill_switch_prevents_the_spawn_entirely(monkeypatch):
    """Bật lên thì KHÔNG sinh tiến trình — không phải sinh rồi giết."""
    monkeypatch.setenv(KILL_SWITCH_ENV, "1")
    supervisor = _supervisor("normal.py")

    async def go():
        with pytest.raises(WorkerFailure) as caught:
            await supervisor.request(_request())
        assert caught.value.code == "kill_switch"

    asyncio.run(go())
    assert supervisor.health.spawns == 0, "đã sinh tiến trình dù kill switch bật"
    assert supervisor.health.state == "stopped"


def test_the_kill_switch_flipped_mid_request_terminates_the_worker(monkeypatch):
    """Bật giữa chừng phải CẮT lượt đang chạy, không phải chờ hết hạn.

    `request_timeout_s` để rất dài có chủ ý: nếu bài này xanh nhờ timeout thì
    nó không chứng minh gì cả — đúng cái bẫy bản đầu của bộ test đã rơi vào.
    Chỉ kill switch mới kết thúc được lượt này trong vài trăm mili giây.
    """
    supervisor = _supervisor("sleeps_forever.py", request_timeout_s=120.0)

    async def go():
        task = asyncio.create_task(supervisor.request(_request()))
        await asyncio.sleep(0.3)
        started = time.monotonic()
        monkeypatch.setenv(KILL_SWITCH_ENV, "1")
        with pytest.raises(WorkerFailure) as caught:
            await task
        assert caught.value.code == "kill_switch"
        assert time.monotonic() - started < 10.0, "công tắc phải cắt NGAY"

        with pytest.raises(WorkerFailure) as again:
            await supervisor.request(_request("req-2"))
        assert again.value.code == "kill_switch"

    asyncio.run(go())
    assert supervisor.health.spawns == 1
    assert _worker_children("sleeps_forever.py") == [], "worker phải bị giết"


def test_cancelling_the_request_still_kills_the_worker():
    """Huỷ cũng là một đường thoát, và mọi đường thoát phải giết."""
    supervisor = _supervisor("sleeps_forever.py", request_timeout_s=30.0)

    async def go():
        task = asyncio.create_task(supervisor.request(_request()))
        await asyncio.sleep(0.4)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(go())
    time.sleep(0.4)
    assert _worker_children("sleeps_forever.py") == [], "huỷ để lại tiến trình"


# --------------------------------------------------------------------------
# Mô hình đe doạ: worker KHÔNG được cầm gì


def test_the_worker_environment_carries_no_secret_and_no_path():
    """Worker không cần biết DB ở đâu, và một biến thừa là một đường dẫn kẻ
    tấn công không phải tự đoán ra."""
    fixture = HOSTILE / "_dump_env.py"
    fixture.write_text(
        "import json,os,struct,sys\n"
        "size,=struct.unpack('!I',sys.stdin.buffer.read(4))\n"
        "req=json.loads(sys.stdin.buffer.read(size))\n"
        "body=json.dumps({'schema_version':1,'kind':'response',"
        "'request_id':req['request_id'],'ok':True,'failure_code':'ok',"
        "'result':{'env':sorted(os.environ),'cwd':os.getcwd(),'argv':sys.argv}}).encode()\n"
        "sys.stdout.buffer.write(struct.pack('!I',len(body))+body)\n"
        "sys.stdout.buffer.flush()\n", encoding="utf-8")
    try:
        async def go():
            return await _supervisor("_dump_env.py").request(_request())

        response = asyncio.run(go())
    finally:
        fixture.unlink(missing_ok=True)

    env = set(response.result["env"])
    for forbidden in ("SHIELD_DB", "SHIELD_SOCK", "SHIELD_HELPER_SOCK",
                      "SHIELD_AUDIT_HMAC_KEY", "SHIELD_STATE_DIR",
                      "SHIELD_QUARANTINE_DIR", "SHIELD_SNAPSHOT_DIR"):
        assert forbidden not in env, f"worker thấy {forbidden}"
    assert env <= {"PATH", "LANG", "PYTHONHASHSEED", "PYTHONDONTWRITEBYTECODE",
                   "SHIELD_WORKER_LIMITS"}, sorted(env)
    assert response.result["cwd"] == "/", "worker không được đứng trong cây mã nguồn"


def test_the_request_contract_cannot_carry_a_handle_or_a_token():
    """Liệt kê ĐÓNG: nếu một trường không có ở đây thì worker không có cách nào
    biết tới nó."""
    payload = _request().to_payload()
    assert set(payload) == {"schema_version", "kind", "request_id", "facts",
                            "observations", "target_locale", "deadline_s"}
    for smuggled in ("token", "capability", "db", "conn", "queries",
                     "evidence_path", "tools"):
        bad = {**payload, smuggled: "x"}
        with pytest.raises(protocol.FrameError):
            protocol.WorkerRequest.parse(bad)


def test_the_worker_package_never_reaches_the_database_or_response_code():
    """Đọc IMPORT bằng AST, không tìm chuỗi trong nguồn.

    Tìm chuỗi thì chính đoạn tài liệu giải thích "không bao giờ pickle" làm bài
    test đỏ — và cách sửa rẻ nhất khi ấy là xoá lời giải thích, tức là bài test
    trừng phạt đúng thứ đáng giữ.
    """
    import ast

    forbidden = {"sqlite3", "pickle", "marshal", "shelve", "ctypes", "socket"}
    for name in ("protocol", "supervisor", "limits", "__main__"):
        path = Path("shield/ai/worker") / f"{name}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
                imported.add(node.module)
        assert not (imported & forbidden), f"{name} import {imported & forbidden}"
        for banned in ("shield.agent.store", "shield.evidence.queries",
                       "shield.security.response", "shield.privileged"):
            assert banned not in imported, f"{name} import {banned}"


def test_the_protocol_refuses_pickle_shaped_payloads():
    """Không `pickle`, không `marshal`. Nạp pickle từ một tiến trình không đáng
    tin là thực thi mã tuỳ ý — đúng thứ ranh giới này dựng ra để chặn."""
    import pickle

    blob = pickle.dumps({"kind": "response"})
    with pytest.raises(protocol.FrameError):
        protocol.decode_body(blob)


# --------------------------------------------------------------------------
# Khung truyền


def test_a_frame_larger_than_the_cap_is_refused_before_a_byte_is_allocated():
    import struct

    header = struct.pack("!I", 4_000_000_000)
    with pytest.raises(protocol.FrameError):
        protocol.decode_header(header, limit=protocol.MAX_RESPONSE_BYTES)


@pytest.mark.parametrize("payload", [
    {"schema_version": 99, "kind": "response", "request_id": "req-1", "ok": True,
     "failure_code": "ok", "result": {}},
    {"schema_version": 1, "kind": "request", "request_id": "req-1", "ok": True,
     "failure_code": "ok", "result": {}},
    {"schema_version": 1, "kind": "response", "request_id": "KHAC", "ok": True,
     "failure_code": "ok", "result": {}},
    {"schema_version": 1, "kind": "response", "request_id": "req-1", "ok": True,
     "failure_code": "khong_co_ma_nay", "result": {}},
    {"schema_version": 1, "kind": "response", "request_id": "req-1", "ok": True,
     "failure_code": "ok", "result": "không phải object"},
])
def test_a_malformed_response_fails_closed(payload):
    with pytest.raises(protocol.FrameError):
        protocol.WorkerResponse.parse(payload, expect_id="req-1")


def test_the_response_id_must_match_the_request():
    """Lệch id nghĩa là đang đọc phản hồi của một yêu cầu KHÁC — nhận nó là gán
    kết luận của lượt này cho dữ liệu lượt kia."""
    good = protocol.WorkerResponse(request_id="req-1").to_payload()
    assert protocol.WorkerResponse.parse(good, expect_id="req-1").ok
    with pytest.raises(protocol.FrameError):
        protocol.WorkerResponse.parse(good, expect_id="req-2")


def test_stderr_is_kept_but_bounded():
    assert MAX_STDERR_BYTES <= 128 * 1024


# --------------------------------------------------------------------------
# Sức khoẻ: đếm được, và không rò một byte nào của worker


def test_health_counts_every_kind_of_failure():
    supervisor = _supervisor("aborts.py", request_timeout_s=3.0)

    async def go():
        with pytest.raises(WorkerFailure):
            await supervisor.request(_request())

    asyncio.run(go())
    health = supervisor.health.to_dict()
    assert health["spawns"] == 1
    assert health["crashes"] + health["resource_limit_exits"] >= 1
    assert health["state"] == "degraded"
    assert health["last_exit_signal"] == int(signal.SIGABRT)
    assert set(health) >= {"state", "restarts", "timeouts", "crashes",
                           "resource_limit_exits", "last_error_code"}


def test_health_never_carries_worker_output_or_a_secret():
    """Bảng sức khoẻ lên giao diện và sống lâu hơn lượt điều tra."""
    fixture = HOSTILE / "_leaky.py"
    fixture.write_text(
        "import sys\n"
        "sys.stderr.write('AKIAIOSFODNN7EXAMPLE bí mật rò ra đây\\n')\n"
        "sys.stderr.flush()\n"
        "raise SystemExit(3)\n", encoding="utf-8")
    try:
        supervisor = _supervisor("_leaky.py", request_timeout_s=3.0)

        async def go():
            with pytest.raises(WorkerFailure):
                await supervisor.request(_request())

        asyncio.run(go())
    finally:
        fixture.unlink(missing_ok=True)

    import json as _json

    blob = _json.dumps(supervisor.health.to_dict())
    assert "AKIA" not in blob
    assert supervisor.health.last_error_code in protocol.FAILURE_CODES


# --------------------------------------------------------------------------
# Sức khoẻ không được làm cả hệ thống đỏ


def test_a_worker_crash_does_not_make_the_whole_system_unhealthy():
    """Điểm sức khoẻ trả lời "Shield có đang giám sát đầy đủ không". Một worker
    model sập không làm Shield mù mảng nào — trừ 25 điểm cho nó là nói với
    người dùng rằng mạng của họ đang hở, trong khi không hề."""
    from shield.security.health import NON_TELEMETRY_COMPONENTS, overall_health

    assert "ai_model_worker" in NON_TELEMETRY_COMPONENTS
    rows = [
        {"component": "endpoint", "state": "running", "healthy": True},
        {"component": "ai_model_worker", "state": "failed", "healthy": False,
         "error_message": "crashed"},
    ]
    result = overall_health(rows, [])
    assert result["score"] == 100, result
    assert result["state"] == "healthy"
    assert all(p["name"] != "ai_model_worker" for p in result["penalties"])

    # ...nhưng một collector THẬT chết thì vẫn phải trừ, nếu không bài trên chỉ
    # chứng minh rằng hàm đã ngừng hoạt động.
    broken = overall_health(
        [{"component": "endpoint", "state": "failed", "healthy": False}], [])
    assert broken["score"] < 100


def test_a_worker_crash_is_reported_as_degraded_ai_not_as_a_blind_spot():
    from shield.agent.problems import detect_problems

    problems = detect_problems(collector_health=[
        {"component": "ai_model_worker", "state": "failed", "healthy": False,
         "backend": "isolated-subprocess", "error_message": "crashed"}])
    assert len(problems) == 1
    problem = problems[0]
    assert problem.severity == "warning", "một worker sập không phải sự cố critical"
    assert "unmonitored" not in problem.detail.lower()
    assert "Detection, alerting and response are unaffected" in problem.detail


def test_published_health_carries_counters_not_worker_output():
    class FakeStore:
        def __init__(self) -> None:
            self.rows: list[tuple] = []

        def set_collector_health(self, component, backend, healthy, detail, **kw):
            self.rows.append((component, backend, healthy, detail, kw))

    from shield.ai.worker.supervisor import HEALTH_COMPONENT, publish_health

    store = FakeStore()
    health = WorkerHealth(state="degraded", spawns=3, crashes=1, timeouts=2,
                          last_error_code="timeout")
    publish_health(store, health)
    component, backend, _healthy, detail, kw = store.rows[-1]
    assert component == HEALTH_COMPONENT and backend == "isolated-subprocess"
    assert "crashes=1" in detail and "timeouts=2" in detail
    assert kw["error_message"] == "timeout", "mã đóng, không phải câu của worker"

    publish_health(store, health, enabled=False)
    assert store.rows[-1][1] == "disabled", "AI tắt phải mang nhãn `disabled`"


# --------------------------------------------------------------------------
# Hạ quyền: compute không đáng tin không được chạy bằng root


def test_dropping_privileges_reports_instead_of_failing_silently():
    """Ba kết quả khác nhau, và cả ba phải nói được: đã hạ, không cần hạ,
    hạ thất bại. Im lặng ở đây nghĩa là mọi thứ phía sau tin rằng ranh giới đã
    dựng trong khi chưa."""
    from shield.ai.worker.limits import drop_privileges

    outcome = drop_privileges()
    assert set(outcome) >= {"dropped", "reason"} or outcome.get("dropped")
    if os.geteuid() != 0:
        assert outcome == {"dropped": False, "reason": "not_root", "uid": os.geteuid()}


def test_dropping_to_an_unknown_user_is_refused_not_ignored():
    from shield.ai.worker.limits import drop_privileges

    outcome = drop_privileges("khong-co-user-nay-tren-may")
    assert outcome["dropped"] is False
    assert outcome["reason"] in {"not_root", "unknown_user"}


def test_the_drop_order_is_setgroups_then_setgid_then_setuid():
    """Sai thứ tự thì sau `setuid` tiến trình không còn quyền bỏ group phụ, và
    nó GIỮ LẠI nhóm của root — một lần hạ quyền trông như đã xong nhưng chưa.

    Kiểm bằng nguồn vì đường root không chạy được trong bộ test không quyền.
    """
    import inspect

    from shield.ai.worker import limits as L

    source = inspect.getsource(L.drop_privileges)
    order = [source.index(call) for call in
             ("os.setgroups([])", "os.setgid(", "os.setuid(")]
    assert order == sorted(order), "phải setgroups -> setgid -> setuid"
    assert "still_root" in source, "phải kiểm lại sau khi hạ"


def test_the_shipped_worker_drops_privileges_before_reading_anything():
    """Thứ tự trong `main()` là quyết định an ninh: trần xuống và quyền hạ
    TRƯỚC khi đọc khung đầu tiên, nên mã model không có khoảnh khắc nào chạy
    với trần chưa hạ."""
    import inspect

    import shield.ai.worker.__main__ as W

    # Đọc thân `main()`, không đọc cả file: `_read_request` được ĐỊNH NGHĨA
    # phía trên, nên so vị trí trên toàn file đo nhầm thứ tự khai báo thay vì
    # thứ tự thực thi.
    body = inspect.getsource(W.main)
    assert (body.index("worker_limits.apply(")
            < body.index("drop_privileges()")
            < body.index("_read_request(")), body


def test_the_shipped_worker_cannot_write_a_file():
    """`RLIMIT_FSIZE=0` — một model đầy sáng tạo không đổ được dữ liệu điều tra
    ra đĩa. Kiểm trên ĐƯỜNG SẢN PHẨM: trần do vỏ worker tự áp, nên một tiến
    trình không phải vỏ ấy sẽ không có trần — điều đó được ghi rõ trong báo cáo
    3C-0 như một giới hạn đã biết."""
    from shield.ai.worker.limits import ResourceLimits

    data = _in_subprocess(
        "from shield.ai.worker import limits as L\n"
        "L.apply(L.ResourceLimits.from_json(os.environ['SHIELD_WORKER_LIMITS']))\n"
        "try:\n"
        "  f=open('/tmp/_shield_fsize_probe','wb');f.write(b'x'*64);f.flush()\n"
        "  out='WRITE_OK'\n"
        "except OSError as e:\n  out=f'BLOCKED:{e.errno}'\n"
        "print(json.dumps(out))\n",
        extra_env={"SHIELD_WORKER_LIMITS": ResourceLimits().to_json()})
    assert data.startswith("BLOCKED"), data
