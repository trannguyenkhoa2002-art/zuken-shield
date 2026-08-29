"""`socket_connect` có mang đúng executable không — hỏi kernel, không suy đoán.

Trước thay đổi này, `socket_connect` chỉ mang `comm`. Đo trên corpus production
13.590 event: chỉ **54,9%** ghép được sang một `exe` qua `process_exec`, và
phần trượt lệch hẳn về các daemon chạy TRƯỚC agent — `systemd-resolve` (3.158
lượt), `chronyd` (1.309), `NetworkManager` (549). Đúng nhóm gọi connect nhiều
nhất là nhóm không bao giờ có executable.

Bài quan trọng nhất ở đây là `test_an_exec_changes_the_executable_mid_process`:
đo trên máy thật, `exec()` KHÔNG đổi `start_ticks`, nên `pid:start_ticks` không
chứng minh được executable không đổi. Bất kỳ bảng nhớ `exe` nào khoá theo danh
tính đó cũng sẽ trả về binary cũ mãi mãi — và không có gì tự báo.

    sudo SHIELD_NETNS_TESTS=1 .venv/bin/python -m pytest tests/test_exe_enrichment_kernel.py -v -s

Không mở cổng nào ra ngoài: mọi kết nối đều tới loopback.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time

import pytest

from shield.agent.bus import Bus
from shield.agent.collectors.kernel import ebpf_exec_loop

pytestmark = [
    pytest.mark.netns,
    pytest.mark.skipif(os.geteuid() != 0, reason="cần root để gắn probe eBPF"),
    pytest.mark.skipif(os.environ.get("SHIELD_NETNS_TESTS") != "1",
                       reason="đặt SHIELD_NETNS_TESTS=1 để chạy có chủ đích"),
]

ATTACH_S = 6.0
SETTLE_S = 2.5


def _run(body, settle_s: float = SETTLE_S, after=None):
    """Gắn probe thật, chạy `body()`, thu event.

    `body` PHẢI là coroutine, và mọi lần chờ trong nó phải là `await`. Một
    `time.sleep()` ở đây chặn event loop, nên `ebpf_exec_loop` không đọc được
    dòng nào suốt thời gian đó — rồi đọc hết một lượt và `at = now()` đóng dấu
    tất cả cùng một khoảnh khắc. Đó chính là thứ đã làm bài exec dưới đây đỏ
    hai lần và làm tôi đổ oan cho bộ đệm của bpftrace: đo lại bằng `nsecs`, cả
    ba mode (mặc định, `-B line`, `-B none`) đều giao NGAY và giống hệt nhau.
    """
    async def scenario():
        bus: Bus = Bus(max_queue_size=4096, overflow_policy="drop_oldest")
        queue = bus.subscribe()
        probe = asyncio.create_task(ebpf_exec_loop(bus))
        try:
            await asyncio.sleep(ATTACH_S)
            result = await body()
            await asyncio.sleep(settle_s)
            events = []
            while not queue.empty():
                events.append(queue.get_nowait())
            stats = bus.stats()
            # Dọn dẹp phải chạy TRONG chính loop này. `asyncio.run()` ở ngoài
            # mở một loop khác, và transport của tiến trình con thuộc loop này
            # — "got Future attached to a different loop".
            if after is not None:
                await after()
            return result, events, stats
        finally:
            probe.cancel()
            try:
                await probe
            except BaseException:
                pass
    return asyncio.run(scenario())


def _connects(events, port):
    return [e for e in events
            if e.kind == "socket_connect" and e.data.get("remote_port") == port]


def _closed_port(family, host):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.bind((host, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.mark.parametrize("family,host,nhan", [
    (socket.AF_INET, "127.0.0.1", "IPv4"),
    (socket.AF_INET6, "::1", "IPv6"),
])
def test_a_connect_carries_the_executable_of_the_calling_process(family, host, nhan):
    port = _closed_port(family, host)

    async def body():
        client = socket.socket(family, socket.SOCK_STREAM)
        client.settimeout(1.0)
        try:
            client.connect((host, port))
            return "connected"
        except OSError as exc:
            return f"{type(exc).__name__}:{exc.errno}"
        finally:
            client.close()

    outcome, events, stats = _run(body)
    hits = _connects(events, port)
    mong_doi = os.path.realpath(sys.executable)
    print(f"\n  {nhan} {host}:{port}  connect()={outcome}  event khớp={len(hits)}")
    for event in hits[:2]:
        print(f"     exe={event.data.get('exe')!r} remote_ip={event.data.get('remote_ip')!r} "
              f"pid={event.data['pid']} start_ticks={event.data.get('start_ticks')!r}")
    # Cổng ĐÓNG: probe nằm ở `sys_enter_connect` nên connect thất bại vẫn phải
    # để lại bằng chứng, và bằng chứng đó vẫn phải mang executable.
    assert hits, f"connect() tới {host} không sinh event nào"
    event = hits[0]
    assert event.data["pid"] == os.getpid()
    assert event.data.get("start_ticks"), "thiếu start_ticks"
    assert event.data.get("exe") == mong_doi, (event.data.get("exe"), mong_doi)
    assert event.data.get("remote_ip") == host, event.data.get("remote_ip")
    assert stats["dropped"] == 0, stats


def test_an_exec_changes_the_executable_mid_process():
    """REGRESSION BẮT BUỘC trên kernel thật — chống bảng nhớ giữ executable cũ.

    Một tiến trình con connect bằng python, RỒI `exec()` sang `curl` và connect
    lần nữa. PID và `start_ticks` giữ nguyên qua exec; `exe` thì không được.

    Cả hai lần connect đi tới một cổng ĐANG NGHE mà KHÔNG BAO GIỜ trả lời, và
    Quãng nghỉ ở đây ngắn, và ĐÚNG là phải ngắn. Hai lần trước bài này đỏ với
    `[None, None]` rồi `['curl', 'curl']`, và tôi đã nới quãng nghỉ lên 20 giây
    để chữa — chữa nhầm chỗ. Nguyên nhân thật: `body()` cũ là hàm đồng bộ chứa
    `time.sleep()`, chạy ngay trong event loop, nên `ebpf_exec_loop` bị chặn
    không đọc được dòng nào; đọc hết một lượt sau đó thì tiến trình đã `exec`
    xong. Đo lại bằng `nsecs` của kernel: bpftrace giao NGAY, và cả ba mode
    (mặc định, `-B line`, `-B none`) giống hệt nhau.

    Bài in ra độ trễ thật của từng event, nên nếu nó đỏ lại thì con số sẽ nói
    ngay là do độ trễ hay do mã.
    """
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)          # nhận vào hàng đợi, KHÔNG accept, không trả lời
    port = server.getsockname()[1]

    ma = (
        "import os,socket,sys,time\n"
        "ticks=open('/proc/self/stat').read().rsplit(')',1)[1].split()[19]\n"
        "print(os.getpid(),ticks,flush=True)\n"
        "s=socket.socket();s.settimeout(2)\n"
        "try: s.connect(('127.0.0.1',%d))\n"
        "except OSError: pass\n"
        "time.sleep(2.0)\n"
        "os.execv('/usr/bin/curl',['curl','-s','--max-time','30','http://127.0.0.1:%d/'])\n"
    ) % (port, port)

    giu = {}
    moc = time.time()

    async def body():
        child = await asyncio.create_subprocess_exec(
            sys.executable, "-c", ma,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        giu["child"] = child
        pid_str, ticks = (await child.stdout.readline()).decode().split()
        await asyncio.sleep(5.0)   # qua quãng nghỉ 2s của con, qua exec, curl đang chờ
        return int(pid_str), ticks

    async def don_dep():
        child = giu.get("child")
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()

    try:
        (pid, ticks), events, stats = _run(body, after=don_dep)
    finally:
        server.close()

    hits = [e for e in _connects(events, port) if e.data["pid"] == pid]
    exes = [e.data.get("exe") for e in hits]
    print(f"\n  tiến trình con pid={pid} start_ticks={ticks}")
    print(f"  {len(hits)} event, exe quan sát được: {exes}")
    for e in hits:
        print(f"     ts-{moc:.0f} = {e.ts - moc:6.2f}s  exe={e.data.get('exe')!r} "
              f"start_ticks={e.data.get('start_ticks')!r} nguon={e.data.get('identity_source')!r}")

    truoc = [e for e in hits if e.data.get("exe") == os.path.realpath(sys.executable)]
    sau = [e for e in hits if (e.data.get("exe") or "").endswith("curl")]
    assert truoc, f"không thấy connect TRƯỚC exec: {exes}"
    assert sau, f"không thấy connect SAU exec mang curl — bảng nhớ đang giữ exe cũ: {exes}"
    # Chính điều làm bảng nhớ theo pid:start_ticks trở nên sai:
    assert truoc[0].data["start_ticks"] == sau[0].data["start_ticks"] == ticks, \
        "start_ticks phải giữ nguyên qua exec — nếu không, bài này không chứng minh được gì"
    assert stats["dropped"] == 0, stats
