"""Phase 2 A1–A5: chiều sâu telemetry, và cái giá của nó.

Năm thay đổi, tất cả xuất phát từ đo đạc trên database thật (1.546.572 event
trong 16,5 ngày), không từ suy đoán:

A1  `parent_start_ticks` -> cây tiến trình. Trước đó: 615.580 event
    `process_exec` sinh ra ĐÚNG 0 cạnh `spawned`.
A2  ảnh chụp procfs có `uid`, `ppid`, `comm` — trước đó không có cái nào,
    trong khi nguồn eBPF cho cùng sự việc thì có cả ba.
A3  trần tốc độ + bộ đếm bỏ cho `conn_watch`/`arp_sniffer`. Trước đó mỗi gói
    tin lên lịch một future, không trần, không đếm.
A4  `Bus.stats()` vào `collector_health`. Trước đó việc bus vứt event là vô hình.
A5  `tcp_ack` từ 41,02% telemetry thành bản đếm theo cửa sổ.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from shield.agent.collectors.flowagg import FlowAggregator
from shield.agent.collectors.kernel import _identity, _parent_identity, _read_proc_identity
from shield.agent.collectors.ratelimit import RateLimiter
from shield.agent.detectors.portscan import PortscanDetector
from shield.common.models import Event
from shield.evidence.resolver import resolve

ROOT = Path(__file__).resolve().parent.parent


# --- A1: cây tiến trình ---


def _fake_proc(tmp_path: Path, pid: int, ppid: int, ticks: str, comm: str = "x") -> None:
    directory = tmp_path / str(pid)
    directory.mkdir(exist_ok=True)
    fields = ["0"] * 22
    fields[1] = str(ppid)
    fields[19] = ticks
    (directory / "stat").write_text(f"{pid} ({comm}) S " + " ".join(fields[1:]))


def test_identity_now_carries_the_parents_start_ticks(tmp_path):
    _fake_proc(tmp_path, 100, 50, "1000")
    _fake_proc(tmp_path, 50, 1, "500")
    identity = _read_proc_identity(100, tmp_path)
    assert identity["ppid"] == 50
    assert identity["parent_start_ticks"] == "500"


def test_a_process_exec_event_now_produces_a_spawned_edge(tmp_path):
    """Đây là toàn bộ lý do A1 tồn tại. `resolver` đã dựng cạnh `spawned` từ
    2.0, nhưng nó cần `parent_start_ticks` mà không collector nào phát ra —
    nên trên 615.580 event thật, số cạnh `spawned` là 0."""
    _fake_proc(tmp_path, 100, 50, "1000")
    _fake_proc(tmp_path, 50, 1, "500")
    data = {"pid": 100, "uid": 0, "comm": "sh", "exe": "/bin/sh"}
    data.update(_identity(100, "process_exec", 1000.0, tmp_path))
    _, edges = resolve(Event(1000.0, "kernel", "process_exec", data))
    assert "spawned" in {edge.relation for edge in edges}


def test_a_missing_parent_produces_no_edge_rather_than_a_guess(tmp_path):
    """Cha đã chết -> không có `start_ticks` -> KHÔNG dựng cạnh. Đoán ở đây là
    gộp hai tiến trình cha khác nhau cùng PID làm một."""
    _fake_proc(tmp_path, 100, 50, "1000")   # pid 50 không tồn tại
    data = {"pid": 100, "uid": 0, "comm": "sh", "exe": "/bin/sh"}
    data.update(_identity(100, "process_exec", 1000.0, tmp_path))
    assert data.get("parent_start_ticks", "") == ""
    _, edges = resolve(Event(1000.0, "kernel", "process_exec", data))
    assert "spawned" not in {edge.relation for edge in edges}


def test_the_parent_lookup_is_not_cached(tmp_path):
    """CỐ Ý không nhớ: PID được dùng lại, và một mục nhớ `ppid -> ticks` trở
    thành SAI ngay khi số PID đó được cấp cho tiến trình khác."""
    _fake_proc(tmp_path, 50, 1, "500")
    assert _parent_identity(50, tmp_path) == "500"
    _fake_proc(tmp_path, 50, 1, "999")      # PID 50 nay là tiến trình khác
    assert _parent_identity(50, tmp_path) == "999"


def test_the_real_local_process_tree_resolves():
    """Chạy trên /proc THẬT. Dữ liệu tổng hợp không chứng minh được rằng cách
    bóc `/proc/<pid>/stat` là đúng với kernel này."""
    identity = _read_proc_identity(os.getpid())
    assert identity is not None
    assert identity["parent_start_ticks"], "không đọc được start_ticks của tiến trình cha"
    data = {"pid": os.getpid(), "uid": os.getuid(), "comm": "python",
            "exe": "/usr/bin/python3"}
    data.update(identity)
    _, edges = resolve(Event(time.time(), "kernel", "process_exec", data))
    assert "spawned" in {edge.relation for edge in edges}


# --- A2: ảnh chụp procfs ---


def test_the_procfs_snapshot_now_matches_the_ebpf_field_set():
    from shield.agent.collectors.endpoint import process_snapshot

    snapshot = process_snapshot()
    assert snapshot, "không đọc được /proc"
    sample = next(iter(snapshot.values()))
    for field in ("pid", "ppid", "uid", "comm", "start_ticks", "exe",
                  "cmdline", "parent_start_ticks"):
        assert field in sample, field


def test_a_procfs_process_event_also_builds_the_tree():
    from shield.agent.collectors.endpoint import process_snapshot

    trees = 0
    for data in process_snapshot().values():
        _, edges = resolve(Event(time.time(), "endpoint", "process_started", data))
        if "spawned" in {edge.relation for edge in edges}:
            trees += 1
    assert trees > 0, "không event procfs nào dựng được cạnh cha-con"


def test_the_command_line_is_redacted_with_the_shared_rules():
    """Dòng lệnh là chỗ mật khẩu hay nằm nhất, và nó ĐƯỢC LƯU vào events rồi
    xuất ra file log."""
    import ast

    source = (ROOT / "shield" / "agent" / "collectors" / "endpoint.py").read_text(
        encoding="utf-8")
    tree = ast.parse(source)
    modules = [node.module for node in ast.walk(tree)
               if isinstance(node, ast.ImportFrom)]
    assert "shield.common.secrets" in modules
    assert "cmdline = redact_text(cmdline)" in source


# --- A3: trần tốc độ ---


def test_the_rate_limiter_counts_what_it_drops():
    limiter = RateLimiter({"tcp_syn": 2})
    assert limiter.allow("tcp_syn", 1000.0)
    assert limiter.allow("tcp_syn", 1000.4)
    assert not limiter.allow("tcp_syn", 1000.9)
    assert limiter.dropped == {"tcp_syn": 1}
    assert "tcp_syn=1" in limiter.drop_summary()
    assert limiter.allow("tcp_syn", 1001.0), "cửa sổ mới phải cấp lại token"


def test_an_unknown_kind_is_refused_not_allowed_by_default():
    assert RateLimiter({}).allow("bat_ky", 1000.0) is False


def test_the_packet_helper_bounds_before_scheduling_on_the_event_loop():
    """Chặn SAU khi đã xếp hàng thì không chặn gì cả.

    Bất biến này theo mã bắt gói sang `shield-packet-collector`: `on_packet`
    của helper chạy trên thread sniff của scapy và chỉ được `call_soon_threadsafe`
    SAU khi đã lọc. Ở phía lõi, trần nằm trong `aggregate_loop`, vốn đã chạy
    trên event loop nên không có gì để lên lịch chéo.
    """
    import ast

    source = (ROOT / "packet_helper" / "__main__.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = False
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == "on_packet"):
            continue
        found = True
        body = ast.dump(node)
        handle_at = body.index("handler")
        schedule_at = body.find("call_soon_threadsafe")
        assert schedule_at == -1 or handle_at < schedule_at, \
            "helper: lọc nằm SAU khi đã lên lịch"
    assert found, "không tìm thấy on_packet trong helper"

    # Publisher có trần hàng đợi, nên một trận lụt gói bỏ bớt thay vì phình RAM.
    assert "asyncio.QueueFull" in source and "MAX_QUEUE" in source


def test_the_core_bounds_packet_events_before_aggregating():
    """Lõi vẫn phải chặn trước khi nạp vào bản đếm."""
    source = (ROOT / "shield" / "agent" / "collectors" / "conn_watch.py").read_text(
        encoding="utf-8")
    limit_at = source.index("limiter.allow(")
    add_at = source.index("aggregator.add(")
    assert limit_at < add_at, "trần nằm SAU khi đã gộp"


def test_conn_watch_no_longer_persists_one_row_per_ack():
    """Bất biến cấu trúc: `tcp_ack` không được đi thẳng lên bus nữa."""
    source = (ROOT / "shield" / "agent" / "collectors" / "conn_watch.py").read_text(
        encoding="utf-8")
    assert 'aggregator.add(' in source
    assert 'kind="tcp_ack"' not in source


# --- A4: bus vào collector_health ---


def test_the_buses_report_themselves_into_collector_health(tmp_path):
    from shield.agent.bus import Bus
    from shield.agent.store import Store
    from shield.security.health import RuntimeMonitor

    store = Store(tmp_path / "s.db", allow_migration=True)
    event_bus, alert_bus = Bus(max_queue_size=4), Bus(max_queue_size=4)
    RuntimeMonitor().sample(store, event_bus, alert_bus, tmp_path)
    rows = {row["component"]: row for row in store.collector_health()}
    assert "event_bus" in rows and "alert_bus" in rows
    assert rows["event_bus"]["healthy"]


def test_a_bus_that_dropped_events_is_not_reported_healthy(tmp_path):
    """Cả hai bus dùng `drop_oldest`: khi đầy chúng VỨT event cũ và chạy tiếp.
    Đó là lựa chọn đúng, nhưng chỉ đúng khi việc vứt nhìn thấy được."""
    from shield.agent.bus import Bus
    from shield.agent.store import Store
    from shield.security.health import RuntimeMonitor

    store = Store(tmp_path / "s.db", allow_migration=True)
    event_bus = Bus(max_queue_size=2, overflow_policy="drop_oldest")
    event_bus.subscribe()
    for index in range(10):
        event_bus.publish_nowait(index)
    assert event_bus.stats()["dropped"] > 0

    RuntimeMonitor().sample(store, event_bus, Bus(), tmp_path)
    row = {r["component"]: r for r in store.collector_health()}["event_bus"]
    assert not row["healthy"]
    assert row["dropped_events"] == event_bus.stats()["dropped"]
    assert "ĐÃ BỎ" in row["detail"]


def test_the_detection_latency_is_unchanged_measured_in_packets(tmp_path):
    """Độ trễ đo bằng SỐ GÓI đã tiêu thụ, không bằng đồng hồ tường: alert được
    đóng dấu bằng `now()`, nên so đồng hồ trên dữ liệu phát lại chỉ đo thời
    gian chạy của chính bài đo.

    Đây là bài kiểm mà thiết kế gộp MỘT tầng đã trượt: connect-scan nhanh bị
    gán nhãn `syn` vì ACK còn nằm trong bộ đếm lúc alert phát đi.
    """
    from shield.agent.store import Store

    def packets(ip, ports, with_ack):
        out = []
        for index, port in enumerate(ports):
            at = 1000.0 + index * 0.025
            out.append((at, "tcp_syn", {"src_ip": ip, "dst_port": port}))
            if with_ack:
                out.append((at + 0.005, "tcp_ack", {"src_ip": ip, "dst_port": port}))
        return out

    def first_alert_index(store_path, stream, aggregate):
        detector = PortscanDetector(Store(store_path, allow_migration=True))
        aggregator = FlowAggregator(bucket_s=60.0) if aggregate else None
        for index, (at, kind, data) in enumerate(stream):
            if aggregator is not None:
                for agg_kind, agg_data in aggregator.drain(at):
                    detector.handle_event(
                        Event(agg_data["last_seen"], "conn_watch", agg_kind, agg_data))
                if kind == "tcp_ack":
                    first = aggregator.add("tcp_ack", data["src_ip"], data["dst_port"], at)
                    if first is not None:
                        seen_kind, seen_data = first
                        detector.handle_event(
                            Event(at, "conn_watch", seen_kind, seen_data))
                    continue
            alerts = detector.handle_event(Event(at, "conn_watch", kind, data))
            if alerts:
                return index, alerts[-1].evidence["scan_type_key"]
        return None, ""

    for name, with_ack in (("connect", True), ("syn", False)):
        stream = packets("198.51.100.5", range(20000, 20040), with_ack)
        before = first_alert_index(tmp_path / f"b{name}.db", stream, aggregate=False)
        after = first_alert_index(tmp_path / f"a{name}.db", stream, aggregate=True)
        assert before == after, f"{name}: {before} != {after}"
        assert before[1] == name


def test_the_aggregate_memory_is_bounded_by_the_cap():
    aggregator = FlowAggregator(bucket_s=60.0, max_keys=100)
    for index in range(10_000):
        aggregator.add("tcp_ack", f"10.0.{index // 256}.{index % 256}", 80, 1000.0)
    assert aggregator.stats()["live_keys"] == 100
    assert aggregator.stats()["overflow"] == 9_900


def test_a_past_burst_does_not_leave_the_collector_unhealthy_forever():
    """Bộ đếm bỏ gói cộng dồn và không bao giờ giảm. Dùng thẳng nó làm điều
    kiện khoẻ/không khoẻ thì một chớp ba gói để component đó ở trạng thái
    "hỏng" mãi mãi — và một component báo hỏng vĩnh viễn dạy người ta bỏ qua
    nó, đúng thứ Shield tồn tại để tránh.

    Đã xảy ra thật trên máy đang chạy: chính lượt `nmap -sn`/`arp-scan` của
    Shield sinh ra chớp ICMP/ARP vượt trần, và `arp_ndp_dhcp` báo `degraded`
    vĩnh viễn vì 3 gói.
    """
    limiter = RateLimiter({"packet": 2})
    for _ in range(5):
        limiter.allow("packet", 1000.0)
    assert limiter.dropped == {"packet": 3}

    assert limiter.losing_data_since_last_check() is True, "vừa mất mà nói không"
    assert limiter.losing_data_since_last_check() is False, "đứng yên mà vẫn báo mất"
    assert limiter.drop_summary(), "mất dấu vết: detail phải vẫn nói đã bỏ bao nhiêu"

    for _ in range(3):
        limiter.allow("packet", 2000.0)
    assert limiter.losing_data_since_last_check() is True, "mất tiếp mà không báo"


def test_the_aggregate_overflow_is_still_treated_as_a_real_loss():
    """Hai loại mất mát khác nhau. Tràn trần KHOÁ là mất hẳn một cặp
    (ip, port) khỏi tầm nhìn — cái đó vẫn phải là không khoẻ."""
    source = (ROOT / "shield" / "agent" / "collectors" / "conn_watch.py").read_text(
        encoding="utf-8")
    assert 'healthy = not stats["overflow"] and not limiter.losing_data_since_last_check()' \
        in source
