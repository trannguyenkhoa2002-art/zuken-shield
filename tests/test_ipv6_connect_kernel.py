"""`socket_connect` có thật sự thấy IPv6 không — hỏi kernel, không suy đoán.

Probe cũ lọc `sa_family == 2` nên `::1` hoàn toàn vô hình: trên database
production, 11.809 event `socket_connect` và **0** cái có địa chỉ IPv6.

Không bài test nào chạy trên máy thường chứng minh được `bpftrace` đọc đúng
`struct sockaddr_in6` từ BTF của kernel NÀY. `--dry-run` cần root, và đọc được
struct cũng khác với bóc đúng thứ tự byte của cổng. Nên file này.

    sudo SHIELD_NETNS_TESTS=1 .venv/bin/python -m pytest tests/test_ipv6_connect_kernel.py -v -s

Không mở cổng nào ra ngoài: mọi kết nối đều tới `::1`.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time

import pytest

from shield.agent.bus import Bus
from shield.agent.collectors.kernel import PROBES, ebpf_exec_loop, probe_support
from shield.common.models import Event

pytestmark = [
    pytest.mark.netns,
    pytest.mark.skipif(os.geteuid() != 0, reason="cần root để gắn probe eBPF"),
    pytest.mark.skipif(os.environ.get("SHIELD_NETNS_TESTS") != "1",
                       reason="đặt SHIELD_NETNS_TESTS=1 để chạy có chủ đích"),
]


def test_the_dual_family_probe_compiles_on_this_kernel():
    """Đây là câu hỏi không trả lời được nếu không có root, và là lý do bài
    này tồn tại. Nếu kernel không đọc được `sockaddr_in6`, `probe_support()`
    phải lùi về phương án IPv4 chứ KHÔNG được mất luôn `socket_connect`."""
    support = asyncio.run(probe_support())
    label = support.supported.get("socket_connect")
    assert label, f"mất hẳn socket_connect: {support.unsupported}"
    print(f"\n  phương án gắn được: {label}")
    if label != "connect tracepoint with IPv4+IPv6 sockaddr":
        pytest.skip(f"kernel này không đọc được sockaddr_in6 — đã lùi về {label!r}")


def _observe(connect_to, port_open: bool):
    """Chạy probe thật, tạo một connect() có kiểm soát, thu event."""
    async def scenario():
        bus: Bus = Bus(max_queue_size=4096, overflow_policy="drop_oldest")
        queue = bus.subscribe()
        probe = asyncio.create_task(ebpf_exec_loop(bus))
        try:
            await asyncio.sleep(6.0)          # bpftrace gắn xong
            server = None
            if port_open:
                server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                server.bind(("::1", 0))
                server.listen(4)
                target = server.getsockname()[1]
            else:
                probe_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                probe_sock.bind(("::1", 0))
                target = probe_sock.getsockname()[1]
                probe_sock.close()            # cổng nay ĐÓNG
            outcome = "connected"
            client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            client.settimeout(1.0)
            try:
                client.connect(connect_to(target))
            except OSError as exc:
                outcome = f"{type(exc).__name__}:{exc.errno}"
            finally:
                client.close()
                if server is not None:
                    server.close()
            await asyncio.sleep(2.0)
            events = []
            while not queue.empty():
                events.append(queue.get_nowait())
            return target, outcome, events, bus.stats()
        finally:
            probe.cancel()
            try:
                await probe
            except BaseException:
                pass
    return asyncio.run(scenario())


def _matching(events, port: int):
    return [e for e in events
            if e.kind == "socket_connect" and e.data.get("remote_port") == port]


def test_a_connect_to_an_open_ipv6_port_is_observed():
    port, outcome, events, stats = _observe(lambda p: ("::1", p), port_open=True)
    hits = _matching(events, port)
    print(f"\n  cổng MỞ ::1:{port}  kết quả connect()={outcome}  event khớp={len(hits)}")
    # `::` là địa chỉ IPv6 HỢP LỆ (unspecified). Nếu probe đọc sai, nó sẽ ghi
    # mọi kết nối IPv6 là đi tới `::` và không có gì trông bất thường cả — đó
    # là lý do bài này khẳng định đúng `::1` chứ không chỉ "có địa chỉ IPv6".
    for event in hits[:2]:
        print(f"     remote_ip={event.data['remote_ip']!r} pid={event.data['pid']} "
              f"start_ticks={event.data.get('start_ticks')!r} event_id={event.event_id[:16]}…")
    assert outcome == "connected", outcome
    assert hits, "connect() tới ::1 không sinh event nào"
    event = hits[0]
    assert event.data["remote_ip"] == "::1", event.data["remote_ip"]
    assert event.data["pid"] == os.getpid()
    assert event.data.get("start_ticks"), "thiếu start_ticks — danh tính không đủ"
    assert event.event_id, "thiếu provenance"
    assert stats["dropped"] == 0, stats


def test_a_refused_ipv6_connect_is_still_observed():
    """Probe nằm ở `sys_enter_connect` — bắt lúc GỌI, trước khi biết kết quả.
    Đó chính là thứ làm nó dùng được cho việc dò cổng: cổng đóng vẫn để lại
    dấu vết."""
    port, outcome, events, _stats = _observe(lambda p: ("::1", p), port_open=False)
    hits = _matching(events, port)
    print(f"\n  cổng ĐÓNG ::1:{port}  kết quả connect()={outcome}  event khớp={len(hits)}")
    assert outcome.startswith("ConnectionRefusedError"), outcome
    assert hits, "connect() bị từ chối mà không sinh event — probe đặt sai chỗ"
    assert hits[0].data["remote_ip"] == "::1"


def test_ipv4_loopback_still_works_after_the_change():
    """Hồi quy: thêm IPv6 không được làm mất IPv4."""
    async def scenario():
        bus: Bus = Bus(max_queue_size=4096, overflow_policy="drop_oldest")
        queue = bus.subscribe()
        probe = asyncio.create_task(ebpf_exec_loop(bus))
        try:
            await asyncio.sleep(6.0)
            server = socket.socket()
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            port = server.getsockname()[1]
            client = socket.socket()
            client.settimeout(1.0)
            client.connect(("127.0.0.1", port))
            client.close()
            server.close()
            await asyncio.sleep(2.0)
            events = []
            while not queue.empty():
                events.append(queue.get_nowait())
            return port, events
        finally:
            probe.cancel()
            try:
                await probe
            except BaseException:
                pass

    port, events = asyncio.run(scenario())
    hits = _matching(events, port)
    print(f"\n  cổng IPv4 127.0.0.1:{port}  event khớp={len(hits)}")
    assert hits, "IPv4 hỏng sau khi thêm IPv6"
    assert hits[0].data["remote_ip"] == "127.0.0.1"
