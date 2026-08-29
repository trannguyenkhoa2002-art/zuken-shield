"""B1: cổng lắng nghe này thuộc tiến trình nào.

Dữ liệu đã có sẵn từ trước — `network_snapshot()` đọc `inode` của socket từ
`/proc/net/tcp` từ lâu — nhưng nó chưa bao giờ được dùng. Thực thể `service`
trong đồ thị có một trường `process`, và trên máy thật nó LUÔN rỗng: collector
không sinh `comm` hay `process` bao giờ. Cùng kiểu hỏng với `parent_start_ticks`
ở A1 và `BehaviorChainDetector` ở 2.0 — khai một khả năng, thiếu một mắt xích,
phần còn lại vẫn xanh.

Không thêm collector: `/proc` đã đủ.
"""

from __future__ import annotations

import dataclasses
import json
import os
import socket
import time
from pathlib import Path

import pytest

from shield.agent.collectors.endpoint import (
    AMBIGUOUS,
    DENIED,
    RESOLVED,
    UNRESOLVED,
    network_snapshot,
    socket_inode_owners,
)
from shield.common.models import Event
from shield.evidence.models import RELATIONS
from shield.evidence.resolver import resolve

ROOT = Path(__file__).resolve().parent.parent


def _fake_proc(tmp_path: Path, pid: int, inodes, ticks: str = "1000",
               readable: bool = True) -> None:
    """Dựng /proc giả: <pid>/stat + <pid>/fd/<n> -> socket:[inode]."""
    directory = tmp_path / str(pid)
    directory.mkdir(exist_ok=True)
    fields = ["0"] * 22
    fields[1] = "1"
    fields[19] = ticks
    (directory / "stat").write_text(f"{pid} (proc) S " + " ".join(fields[1:]))
    fd = directory / "fd"
    fd.mkdir(exist_ok=True)
    for index, inode in enumerate(inodes):
        try:
            (fd / str(index)).symlink_to(f"socket:[{inode}]")
        except FileExistsError:
            pass
    if not readable:
        os.chmod(fd, 0o000)


# --- 1..3: inode -> pid -> start_ticks -> danh tính ---


def test_an_inode_resolves_to_the_pid_holding_it(tmp_path):
    _fake_proc(tmp_path, 100, ["555"], ticks="4242")
    _fake_proc(tmp_path, 101, ["999"], ticks="1")
    result = socket_inode_owners(["555"], tmp_path)["555"]
    assert result["observed_pids"] == [100]
    assert result["resolution"] == RESOLVED


def test_the_owner_carries_the_start_ticks_read_from_proc(tmp_path):
    """PID một mình KHÔNG phải danh tính. Linux dùng lại số PID."""
    _fake_proc(tmp_path, 100, ["555"], ticks="4242")
    owners = socket_inode_owners(["555"], tmp_path)["555"]["owners"]
    assert owners == [{"pid": 100, "start_ticks": "4242"}]


def test_the_listener_event_becomes_a_listens_on_edge(tmp_path):
    event = Event(1000.0, "endpoint", "listener_opened", {
        "protocol": "tcp4", "ip": "0.0.0.0", "port": 8080, "inode": "555",
        "owners": [{"pid": 100, "start_ticks": "4242"}],
        "observed_pids": [100], "resolution": RESOLVED,
    })
    entities, edges = resolve(event)
    kinds = {e.entity_type for e in entities}
    assert {"host", "service", "process"} <= kinds
    relations = [e.relation for e in edges]
    assert "listens_on" in relations
    process = next(e for e in entities if e.entity_type == "process")
    assert process.canonical_key.endswith(":100:4242")


# --- 4: PID reuse ---


def test_pid_reuse_does_not_merge_two_processes(tmp_path):
    """Cùng pid, `start_ticks` khác nhau -> hai thực thể riêng. Nếu gộp, hành
    vi của tiến trình này bị gán cho tiến trình khác."""
    keys = set()
    for ticks in ("100", "200"):
        _, edges = resolve(Event(1000.0, "endpoint", "listener_opened", {
            "protocol": "tcp4", "port": 8080, "inode": "1",
            "owners": [{"pid": 100, "start_ticks": ticks}], "resolution": RESOLVED}))
        entities, _ = resolve(Event(1000.0, "endpoint", "listener_opened", {
            "protocol": "tcp4", "port": 8080, "inode": "1",
            "owners": [{"pid": 100, "start_ticks": ticks}], "resolution": RESOLVED}))
        keys |= {e.canonical_key for e in entities if e.entity_type == "process"}
    assert len(keys) == 2, keys


# --- 5..6: không đoán ---


def test_a_process_that_exits_mid_resolve_produces_no_owner(tmp_path):
    """fd trỏ đúng inode nhưng `stat` không còn: tiến trình đã thoát giữa hai
    bước. Bịa một danh tính ở đây sẽ gộp nó với mọi tiến trình từng mang số
    PID đó."""
    directory = tmp_path / "100"
    (directory / "fd").mkdir(parents=True)
    (directory / "fd" / "0").symlink_to("socket:[555]")
    # KHÔNG có stat
    result = socket_inode_owners(["555"], tmp_path)["555"]
    assert result["observed_pids"] == [100], "pid quan sát được vẫn phải ghi lại"
    assert result["owners"] == []
    assert result["resolution"] == UNRESOLVED


def test_an_unresolved_listener_builds_a_service_but_no_process(tmp_path):
    entities, edges = resolve(Event(1000.0, "endpoint", "listener_opened", {
        "protocol": "tcp4", "port": 8080, "inode": "555",
        "owners": [], "observed_pids": [100], "resolution": UNRESOLVED}))
    assert {e.entity_type for e in entities} == {"host", "service"}
    assert [e.relation for e in edges] == ["ran_on"]
    service = next(e for e in entities if e.entity_type == "service")
    assert service.attributes["owner_resolution"] == UNRESOLVED
    assert service.attributes["observed_pids"] == [100], \
        "pid đã thấy phải giữ lại như một quan sát, dù không dựng cạnh"


def test_an_inode_nobody_holds_resolves_to_nothing(tmp_path):
    _fake_proc(tmp_path, 100, ["999"])
    assert socket_inode_owners(["555"], tmp_path)["555"]["owners"] == []


# --- 7: permission ---


def test_a_directory_we_may_not_read_is_reported_as_denied_not_empty(tmp_path):
    """"Không được phép nhìn" KHÁC "không có gì để thấy". Gộp hai cái đó lại
    là nói với người điều tra rằng cổng này không có chủ."""
    if os.getuid() == 0:
        pytest.skip("root đọc được mọi nơi")
    _fake_proc(tmp_path, 100, ["555"], readable=False)
    try:
        result = socket_inode_owners(["555"], tmp_path)["555"]
        assert result["resolution"] == DENIED
        assert result["owners"] == []
    finally:
        os.chmod(tmp_path / "100" / "fd", 0o755)


def test_permission_errors_do_not_stop_the_scan(tmp_path):
    if os.getuid() == 0:
        pytest.skip("root đọc được mọi nơi")
    _fake_proc(tmp_path, 100, ["555"], readable=False)
    _fake_proc(tmp_path, 101, ["777"], ticks="7")
    try:
        result = socket_inode_owners(["555", "777"], tmp_path)
        assert result["777"]["resolution"] == RESOLVED
        assert result["555"]["resolution"] == DENIED
    finally:
        os.chmod(tmp_path / "100" / "fd", 0o755)


# --- 8: mơ hồ ---


def test_two_processes_holding_one_socket_are_both_recorded(tmp_path):
    """fork kế thừa fd, hoặc SO_REUSEPORT. Bốc một cái làm "chủ sở hữu" là bịa."""
    _fake_proc(tmp_path, 100, ["555"], ticks="1")
    _fake_proc(tmp_path, 101, ["555"], ticks="2")
    result = socket_inode_owners(["555"], tmp_path)["555"]
    assert result["resolution"] == AMBIGUOUS
    assert [o["pid"] for o in result["owners"]] == [100, 101], "thứ tự phải cố định"

    entities, edges = resolve(Event(1000.0, "endpoint", "listener_opened", {
        "protocol": "tcp4", "port": 8080, "inode": "555", **result}))
    listens = [e for e in edges if e.relation == "listens_on"]
    assert len(listens) == 2, "mơ hồ thì dựng cạnh cho TẤT CẢ, không chọn một"


def test_the_owner_order_is_deterministic(tmp_path):
    for pid in (103, 101, 102):
        _fake_proc(tmp_path, pid, ["555"], ticks=str(pid))
    first = socket_inode_owners(["555"], tmp_path)
    second = socket_inode_owners(["555"], tmp_path)
    assert first == second
    assert [o["pid"] for o in first["555"]["owners"]] == [101, 102, 103]


# --- 9..10: IPv4 / IPv6 ---


def test_ipv4_and_ipv6_on_the_same_port_are_two_services():
    """Trước B1 khoá thực thể luôn là "tcp" nên hai socket khác nhau gộp thành
    MỘT node — graph nói dối một cách thuyết phục."""
    keys = set()
    for protocol in ("tcp4", "tcp6"):
        entities, _ = resolve(Event(1000.0, "endpoint", "listener_opened", {
            "protocol": protocol, "port": 443, "inode": "1",
            "owners": [], "resolution": UNRESOLVED}))
        keys |= {e.canonical_key for e in entities if e.entity_type == "service"}
    assert len(keys) == 2, keys


def test_the_collector_reads_all_four_protocol_families(tmp_path):
    """Đọc bằng HÀNH VI, không bằng chuỗi trong mã: một bài test so chuỗi sẽ
    đỏ mỗi lần ai đó xuống dòng, và xanh khi logic đã hỏng."""
    from shield.agent.collectors.endpoint import network_snapshot

    header = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
              "retrnsmt   uid  timeout inode ref pointer drops\n")
    rows = {
        "tcp":  " 0: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 1000 0 11 2 0 0",
        "tcp6": " 0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 0:0 0:0 0 1000 0 12 2 0 0",
        "udp":  " 0: 0100007F:0035 00000000:0000 07 0:0 0:0 0 1000 0 13 2 0 0",
        "udp6": " 0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 0:0 0:0 0 1000 0 14 2 0 0",
    }
    for name, row in rows.items():
        (tmp_path / name).write_text(header + row + "\n")
    protocols = {item["protocol"] for item in network_snapshot(tmp_path).values()}
    assert protocols == {"tcp4", "tcp6", "udp4", "udp6"}


# --- 11..12: đồ thị ---


def test_listens_on_is_a_declared_relation():
    assert "listens_on" in RELATIONS


def test_restarting_produces_the_same_edge_not_a_duplicate(tmp_path):
    """Cùng một listener quan sát lại sau khi khởi động lại phải cho cùng khoá
    thực thể và cùng quan hệ — trùng về mặt ngữ nghĩa là hai node cho một thứ."""
    payload = {"protocol": "tcp4", "port": 8080, "inode": "555",
               "owners": [{"pid": 100, "start_ticks": "4242"}], "resolution": RESOLVED}
    first = resolve(Event(1000.0, "endpoint", "listener_opened", dict(payload)))
    second = resolve(Event(2000.0, "endpoint", "listener_opened", dict(payload)))
    assert {e.canonical_key for e in first[0]} == {e.canonical_key for e in second[0]}
    assert {(e.src_id, e.relation, e.dst_id) for e in first[1]} == \
           {(e.src_id, e.relation, e.dst_id) for e in second[1]}


def test_every_edge_traces_back_to_the_listener_event():
    event = Event(1000.0, "endpoint", "listener_opened", {
        "protocol": "tcp4", "port": 8080, "inode": "555",
        "owners": [{"pid": 100, "start_ticks": "4242"}], "resolution": RESOLVED})
    _, edges = resolve(event)
    assert edges
    for edge in edges:
        assert edge.evidence_refs == (event.evidence_ref(),), edge.relation
        assert event.event_id in edge.evidence_refs[0]


# --- 13: AI ---


def test_the_ai_kill_switch_does_not_change_the_result(tmp_path, monkeypatch):
    from shield.ai.capability import KILL_SWITCH_ENV

    _fake_proc(tmp_path, 100, ["555"], ticks="4242")
    baseline = socket_inode_owners(["555"], tmp_path)
    monkeypatch.setenv(KILL_SWITCH_ENV, "1")
    assert socket_inode_owners(["555"], tmp_path) == baseline


def test_the_resolver_does_not_import_the_ai_package():
    import ast

    for relative in ("shield/evidence/resolver.py",
                     "shield/agent/collectors/endpoint.py"):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = (node.module or "") if isinstance(node, ast.ImportFrom) else (
                ",".join(a.name for a in node.names) if isinstance(node, ast.Import) else "")
            assert "shield.ai" not in module, f"{relative}: {module}"


# --- 14: chi phí ---


def test_one_scan_answers_every_inode_at_once(tmp_path):
    """Quét một lượt cho MỖI inode sẽ nhân 26 ms lên số cổng vừa mở."""
    for pid in range(100, 140):
        _fake_proc(tmp_path, pid, [str(pid * 10)], ticks=str(pid))
    wanted = [str(pid * 10) for pid in range(100, 140)]

    reads = {"count": 0}
    real_listdir = os.listdir

    def counting(path, *args, **kwargs):
        if str(path).endswith("/fd"):
            reads["count"] += 1
        return real_listdir(path, *args, **kwargs)

    import shield.agent.collectors.endpoint as module
    original = module.os.listdir
    module.os.listdir = counting
    try:
        result = socket_inode_owners(wanted, tmp_path)
    finally:
        module.os.listdir = original
    assert len(result) == 40
    assert reads["count"] == 40, \
        f"quét {reads['count']} lượt cho 40 inode — phải đúng 1 lượt qua /proc"


def test_resolving_nothing_costs_nothing(tmp_path):
    assert socket_inode_owners([], tmp_path) == {}
    assert socket_inode_owners(["", "0"], tmp_path) == {}


# --- 15: không thêm truy vấn database ---


def test_b1_adds_no_database_lookup():
    """Phân giải chủ sở hữu đọc `/proc`, không đọc database — nên không có
    query nào để lập kế hoạch, và không có index nào để thiếu."""
    import ast

    tree = ast.parse((ROOT / "shield" / "agent" / "collectors" / "endpoint.py")
                     .read_text(encoding="utf-8"))
    function = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "socket_inode_owners")
    names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)}
    for forbidden in ("execute", "conn", "sqlite3", "Store", "cursor"):
        assert forbidden not in names, f"chạm database: {forbidden}"


# --- đối chiếu với hệ thống thật ---


def test_a_real_listener_of_this_process_resolves_to_this_process():
    """Không kết luận VERIFIED nếu chỉ test tổng hợp. Mở một socket thật của
    chính tiến trình test và đối chiếu với `/proc/<pid>/stat`."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    try:
        port = server.getsockname()[1]
        mine = [item for item in network_snapshot().values() if item["port"] == port]
        assert mine, "listener vừa mở không xuất hiện trong /proc/net/tcp"
        inode = mine[0]["inode"]
        result = socket_inode_owners([inode])[inode]
        assert result["resolution"] == RESOLVED
        owner, = result["owners"]
        assert owner["pid"] == os.getpid()

        stat = Path(f"/proc/{os.getpid()}/stat").read_text()
        assert owner["start_ticks"] == stat[stat.rfind(")") + 2:].split()[19]
    finally:
        server.close()


def test_a_forked_child_makes_the_real_listener_ambiguous():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    child = os.fork()
    if child == 0:
        time.sleep(2)
        os._exit(0)
    try:
        time.sleep(0.4)
        inode = [item for item in network_snapshot().values()
                 if item["port"] == server.getsockname()[1]][0]["inode"]
        result = socket_inode_owners([inode])[inode]
        assert result["resolution"] == AMBIGUOUS
        assert {os.getpid(), child} <= set(result["observed_pids"])
    finally:
        os.waitpid(child, 0)
        server.close()


# --- UDP: đóng khoảng mù 17 cổng ---
#
# UDP KHÔNG có trạng thái nghe. Chép tiêu chí `st=0A` của TCP sang đây sẽ im
# lặng không thấy gì — UDP không bao giờ mang trạng thái đó. Thứ duy nhất
# procfs phân biệt được là socket đã `connect()` hay chưa, và đó cũng chính là
# tiêu chí `ss -lnu` dùng.

def _proc_net(tmp_path: Path, name: str, rows: list[str]) -> None:
    header = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
              "retrnsmt   uid  timeout inode ref pointer drops\n")
    (tmp_path / name).write_text(header + "".join(r + "\n" for r in rows))


def _udp_row(local: str, inode: str, state: str = "07",
             rem: str = "00000000:0000") -> str:
    return (f" 2782: {local} {rem} {state} 00000000:00000000 00:00000000 "
            f"00000000  1000        0 {inode} 2 0000000000000000 0")


def test_an_unconnected_udp_socket_is_reported(tmp_path):
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp", [_udp_row("0100007F:0035", "999")])
    snapshot = network_snapshot(tmp_path)
    item, = snapshot.values()
    assert item["protocol"] == "udp4"
    assert (item["ip"], item["port"], item["inode"]) == ("127.0.0.1", 53, "999")
    assert item["udp_state"] == "unconnected"


def test_a_connected_udp_socket_is_not_reported_as_a_listener(tmp_path):
    """`st=01` + có địa chỉ đối tác = socket client đã `connect()`. `ss -lnu`
    cũng loại nó ra; đo trên máy thật: 3 socket loại này, cả hai bên đều bỏ."""
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp", [
        _udp_row("0100007F:0035", "1", state="01", rem="08080808:0035"),
        _udp_row("0100007F:0036", "2", state="07"),
    ])
    ports = {item["port"] for item in network_snapshot(tmp_path).values()}
    assert ports == {54}


def test_a_socket_with_a_peer_but_state_07_is_still_excluded(tmp_path):
    """Hai điều kiện, không phải một. Chỉ xét `st` sẽ nhận nhầm socket đã nối
    mà kernel còn để ở trạng thái cũ."""
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp", [_udp_row("0100007F:0035", "1", rem="08080808:1F90")])
    assert network_snapshot(tmp_path) == {}


def test_the_tcp_listen_criterion_is_not_copied_to_udp(tmp_path):
    """UDP không bao giờ mang `st=0A`. Nếu ai đó chép tiêu chí TCP sang, bảng
    UDP sẽ luôn rỗng và trông y hệt "máy này không mở cổng UDP nào"."""
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp", [_udp_row("0100007F:0035", "1", state="0A")])
    assert network_snapshot(tmp_path) == {}


def test_a_wildcard_bind_is_decoded(tmp_path):
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp", [_udp_row("00000000:14E9", "1")])
    item, = network_snapshot(tmp_path).values()
    assert (item["ip"], item["port"]) == ("0.0.0.0", 5353)


def test_an_ipv6_udp_socket_is_decoded_with_the_right_byte_order(tmp_path):
    """procfs lưu mỗi từ 32 bit của IPv6 theo thứ tự byte của MÁY. Bóc sai thì
    ra một địa chỉ hợp lệ nhưng SAI — kiểu hỏng khó thấy nhất."""
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp6",
              [_udp_row("00000000000000000000000001000000:14E9", "1")])
    item, = network_snapshot(tmp_path).values()
    assert item["protocol"] == "udp6"
    assert item["ip"] == "::1" and item["port"] == 5353


def test_an_ipv6_wildcard_bind_is_decoded(tmp_path):
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp6",
              [_udp_row("00000000000000000000000000000000:0035", "1")])
    item, = network_snapshot(tmp_path).values()
    assert item["ip"] == "::"


def test_two_udp_sockets_on_the_same_address_stay_separate(tmp_path):
    """Đo được trên máy thật: hai lần tham gia multicast 239.255.255.250:3702
    với hai inode khác nhau. Khoá không có inode sẽ gộp chúng và mất một cái."""
    from shield.agent.collectors.endpoint import network_snapshot

    _proc_net(tmp_path, "udp", [_udp_row("FAFFFFEF:0E76", "111"),
                                _udp_row("FAFFFFEF:0E76", "222")])
    snapshot = network_snapshot(tmp_path)
    assert len(snapshot) == 2
    assert {item["inode"] for item in snapshot.values()} == {"111", "222"}


def test_an_ephemeral_port_is_recorded_but_never_filtered_on(tmp_path):
    """Một socket chưa nối chỉ dùng để `sendto()` KHÔNG phân biệt được với một
    server socket — `ss -lnu` cũng vậy. Ghi nhận là quan sát; lọc theo nó là
    đoán, và đoán sai theo hướng im lặng là kiểu hỏng tệ nhất."""
    from shield.agent.collectors.endpoint import network_snapshot

    (tmp_path / "sys" / "net" / "ipv4").mkdir(parents=True)
    (tmp_path / "sys/net/ipv4/ip_local_port_range").write_text("32768\t60999\n")
    _proc_net(tmp_path, "udp", [_udp_row("00000000:8EA6", "1"),   # 36518
                                _udp_row("00000000:0035", "2")])  # 53
    by_port = {item["port"]: item for item in network_snapshot(tmp_path).values()}
    assert set(by_port) == {36518, 53}, "cổng tạm thời bị LỌC MẤT"
    assert by_port[36518]["ephemeral_port"] is True
    assert by_port[53]["ephemeral_port"] is False


def test_tcp_and_udp_are_separate_services_in_the_graph():
    """Cổng 53 TCP và cổng 53 UDP là hai dịch vụ khác nhau."""
    keys = set()
    for protocol in ("tcp4", "udp4"):
        entities, _ = resolve(Event(1000.0, "endpoint", "listener_opened", {
            "protocol": protocol, "port": 53, "inode": "1",
            "owners": [], "resolution": UNRESOLVED}))
        keys |= {e.canonical_key for e in entities if e.entity_type == "service"}
    assert len(keys) == 2, keys


def test_a_udp_listener_resolves_to_its_owning_process(tmp_path):
    """B1 dùng lại nguyên vẹn: cùng `socket_inode_owners`, cùng `listens_on`,
    cùng luật danh tính. Không quan hệ mới, không collector mới."""
    _fake_proc(tmp_path, 100, ["555"], ticks="4242")
    result = socket_inode_owners(["555"], tmp_path)["555"]
    entities, edges = resolve(Event(1000.0, "endpoint", "listener_opened", {
        "protocol": "udp4", "ip": "0.0.0.0", "port": 5353, "inode": "555", **result}))
    assert result["resolution"] == RESOLVED
    listens = [e for e in edges if e.relation == "listens_on"]
    assert len(listens) == 1
    service = next(e for e in entities if e.entity_type == "service")
    assert service.canonical_key.endswith(":udp4:[0.0.0.0]:5353")


def test_udp_reuses_the_existing_relation_set():
    """Không thêm quan hệ nào cho UDP."""
    assert "listens_on" in RELATIONS
    assert len(RELATIONS) == 11


def test_a_real_udp_listener_of_this_process_resolves(tmp_path):
    """Không kết luận VERIFIED nếu chỉ test tổng hợp."""
    import socket as socket_module

    server = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    try:
        port = server.getsockname()[1]
        from shield.agent.collectors.endpoint import network_snapshot

        mine = [item for item in network_snapshot().values()
                if item["port"] == port and item["protocol"] == "udp4"]
        assert mine, "socket UDP vừa mở không xuất hiện trong /proc/net/udp"
        result = socket_inode_owners([mine[0]["inode"]])[mine[0]["inode"]]
        assert result["resolution"] == RESOLVED
        assert result["owners"][0]["pid"] == os.getpid()
    finally:
        server.close()


def test_a_connected_udp_socket_of_this_process_is_excluded():
    """Cùng một socket: trước `connect()` thì thấy, sau `connect()` thì không."""
    import socket as socket_module

    from shield.agent.collectors.endpoint import network_snapshot

    sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        port = sock.getsockname()[1]
        assert any(item["port"] == port and item["protocol"] == "udp4"
                   for item in network_snapshot().values())
        sock.connect(("127.0.0.1", 9))
        assert not any(item["port"] == port and item["protocol"] == "udp4"
                       for item in network_snapshot().values())
    finally:
        sock.close()


def test_shield_sees_exactly_what_ss_sees():
    """Đối chiếu live với `ss`. Mọi chênh lệch phải giải thích được, không đoán."""
    import shutil
    import subprocess

    if not shutil.which("ss"):
        pytest.skip("không có ss")
    from shield.agent.collectors.endpoint import network_snapshot

    snapshot = network_snapshot()
    for flag, prefix in (("-lntH", "tcp"), ("-lnuH", "udp")):
        expected = len([line for line in subprocess.run(
            ["ss", flag], capture_output=True, text=True).stdout.splitlines() if line.strip()])
        got = len([i for i in snapshot.values() if i["protocol"].startswith(prefix)])
        assert got == expected, f"{prefix}: Shield thấy {got}, ss thấy {expected}"


# --- listener có TRƯỚC khi Shield khởi động ---
#
# Ảnh chụp đầu tiên của `endpoint_loop` chỉ làm mốc so sánh, nên 39 socket đang
# mở trên máy thật (22 TCP + 17 UDP) chưa bao giờ sinh ra event nào. Trên máy
# khởi động dịch vụ trước Shield, đó là phần lớn bề mặt mạng.
#
# Nhưng phát chúng dưới dạng `listener_opened` là BỊA thời điểm mở.

import asyncio as _asyncio

from shield.agent.bus import Bus
from shield.agent.collectors.endpoint import emit_bootstrap_listeners
from shield.agent.detectors.endpoint import (
    BOOTSTRAP_ALERT_COOLDOWN_S,
    SENSITIVE_LISTENER_PORTS,
    EndpointDetector,
)


def _drain(bus_queue) -> list:
    out = []
    while not bus_queue.empty():
        out.append(bus_queue.get_nowait())
    return out


def _bootstrap(network: dict) -> list:
    async def scenario():
        bus: Bus = Bus(max_queue_size=1024, overflow_policy="drop_oldest")
        queue = bus.subscribe()
        await emit_bootstrap_listeners(bus, network)
        return _drain(queue)
    return _asyncio.run(scenario())


def test_a_tcp_listener_present_at_startup_is_observed_not_opened():
    events = _bootstrap({"k": {"protocol": "tcp4", "ip": "0.0.0.0", "port": 22,
                               "inode": "1"}})
    assert [e.kind for e in events] == ["listener_observed"]
    assert events[0].data["bootstrap"] is True
    assert events[0].data["observed_at"] > 0
    assert events[0].data["agent_started_ts"] > 0


def test_a_udp_listener_present_at_startup_is_observed_too():
    events = _bootstrap({"k": {"protocol": "udp6", "ip": "::", "port": 5353,
                               "inode": "2", "udp_state": "unconnected"}})
    assert [e.kind for e in events] == ["listener_observed"]
    assert events[0].data["protocol"] == "udp6"


def test_the_bootstrap_event_never_claims_an_opening_time():
    """Shield không biết cổng mở từ bao giờ. Một trường `opened_at` — dù để
    bằng thời điểm quan sát — là một mốc thời gian bịa ra, và nó sẽ được đọc
    như bằng chứng."""
    events = _bootstrap({"k": {"protocol": "tcp4", "port": 445, "inode": "1"}})
    for forbidden in ("opened_at", "inferred_open_time", "opened_ts", "start_time"):
        assert forbidden not in events[0].data, forbidden


def test_nothing_is_emitted_when_there_are_no_listeners():
    assert _bootstrap({}) == []


def test_a_listener_opened_after_startup_keeps_the_live_semantics():
    """Hai loại event tồn tại song song và KHÔNG được lẫn nhau."""
    detector = EndpointDetector()
    live, = detector.handle_event(Event(1.0, "endpoint", "listener_opened",
                                        {"protocol": "tcp4", "port": 445, "inode": "1"}))
    boot, = detector.handle_event(Event(1.0, "endpoint", "listener_observed",
                                        {"protocol": "tcp4", "port": 445, "inode": "1"}))
    assert live.rule_id == "ENDPOINT_SENSITIVE_LISTENER_OPENED"
    assert boot.rule_id == "RISKY_LISTENER_PRESENT_AT_STARTUP"
    assert live.rule_id != boot.rule_id


# --- đồ thị ---


def test_the_service_never_summarises_how_it_was_discovered():
    """`upsert_entity` ghi đè toàn bộ thuộc tính, nên một trường `discovery`
    trên node sẽ nói "lần quan sát gần nhất thuộc loại nào" trong khi tên hứa
    "phát hiện lần đầu bằng cách nào".

    Nguồn sự thật là chuỗi bằng chứng: cạnh -> evidence_ref -> event -> kind.
    Bảng `events` là append-only nên nó trả lời được cả lần đầu, lần gần nhất
    và số lần mỗi loại.
    """
    for kind in ("listener_observed", "listener_opened"):
        entities, edges = resolve(Event(1000.0, "endpoint", kind, {
            "protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
            "owners": [{"pid": 7, "start_ticks": "99"}], "resolution": RESOLVED}))
        service = next(e for e in entities if e.entity_type == "service")
        assert "discovery" not in service.attributes
        # nhưng vẫn truy ngược được, qua bằng chứng
        assert all(e.evidence_refs for e in edges)


def test_the_discovery_history_is_recoverable_from_the_evidence_chain(tmp_path):
    from shield.agent.store import Store

    store = Store(tmp_path / "s.db", allow_migration=True)
    payload = {"protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
               "owners": [{"pid": 7, "start_ticks": "99"}], "resolution": RESOLVED}
    for ts, kind in ((1000.0, "listener_opened"), (2000.0, "listener_observed")):
        event = Event(ts, "endpoint", kind, dict(payload))
        store.insert_event(event)
        store.graph_ingest_event(event)
    refs = set()
    for (raw,) in store.conn.execute(
            "SELECT evidence_refs FROM graph_edges WHERE relation='listens_on'"):
        refs |= {r.split(":", 1)[1] for r in json.loads(raw)}
    kinds = {row[0] for row in store.conn.execute(
        "SELECT kind FROM events WHERE event_id != '' AND event_id IN "
        f"({','.join('?' * len(refs))})", sorted(refs))}
    assert kinds == {"listener_opened", "listener_observed"}


def test_a_bootstrap_listener_builds_the_same_process_edge():
    entities, edges = resolve(Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "udp4", "ip": "0.0.0.0", "port": 5353, "inode": "1",
        "owners": [{"pid": 7, "start_ticks": "99"}], "resolution": RESOLVED}))
    assert "listens_on" in {edge.relation for edge in edges}
    process = next(e for e in entities if e.entity_type == "process")
    assert process.canonical_key.endswith(":7:99")


def test_an_unresolved_bootstrap_listener_builds_no_process_edge():
    entities, edges = resolve(Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "port": 445, "inode": "1",
        "owners": [], "observed_pids": [4242], "resolution": UNRESOLVED}))
    assert {e.entity_type for e in entities} == {"host", "service"}
    assert [e.relation for e in edges] == ["ran_on"]
    service = next(e for e in entities if e.entity_type == "service")
    assert service.attributes["observed_pids"] == [4242]


def test_two_bootstrap_owners_produce_two_edges_not_a_choice():
    _entities, edges = resolve(Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "port": 445, "inode": "1", "resolution": AMBIGUOUS,
        "owners": [{"pid": 7, "start_ticks": "1"}, {"pid": 8, "start_ticks": "2"}]}))
    assert len([e for e in edges if e.relation == "listens_on"]) == 2


def test_restarting_produces_the_same_graph_keys(tmp_path):
    """Phát lại mỗi lần khởi động KHÔNG được nhân bản thực thể hay cạnh."""
    payload = {"protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
               "owners": [{"pid": 7, "start_ticks": "99"}], "resolution": RESOLVED}
    first = resolve(Event(1000.0, "endpoint", "listener_observed", dict(payload)))
    second = resolve(Event(9000.0, "endpoint", "listener_observed", dict(payload)))
    assert {e.canonical_key for e in first[0]} == {e.canonical_key for e in second[0]}
    assert {(e.src_id, e.relation, e.dst_id) for e in first[1]} == \
           {(e.src_id, e.relation, e.dst_id) for e in second[1]}


def test_restarting_increases_the_observation_count_not_the_row_count(tmp_path):
    from shield.agent.store import Store

    store = Store(tmp_path / "s.db", allow_migration=True)
    payload = {"protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
               "owners": [{"pid": 7, "start_ticks": "99"}], "resolution": RESOLVED}
    for ts in (1000.0, 9000.0, 20000.0):
        # Event phải vào bảng `events` TRƯỚC: đồ thị từ chối cạnh có tham chiếu
        # bằng chứng không tồn tại, và đó là bất biến đúng.
        event = Event(ts, "endpoint", "listener_observed", dict(payload))
        store.insert_event(event)
        store.graph_ingest_event(event)
    rows = store.conn.execute(
        "SELECT observation_count FROM graph_entities WHERE entity_type='service'").fetchall()
    assert len(rows) == 1, "khởi động lại nhân bản thực thể dịch vụ"
    assert rows[0][0] == 3
    assert store.conn.execute(
        "SELECT COUNT(*) FROM graph_edges WHERE relation='listens_on'").fetchone()[0] == 1


def test_every_bootstrap_edge_traces_back_to_its_event():
    event = Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "port": 445, "inode": "1",
        "owners": [{"pid": 7, "start_ticks": "99"}], "resolution": RESOLVED})
    _entities, edges = resolve(event)
    assert edges
    for edge in edges:
        assert edge.evidence_refs == (event.evidence_ref(),)
        assert event.event_id in edge.evidence_refs[0]


# --- baseline hành vi KHÔNG được chạm tới ---


def test_the_bootstrap_kind_never_enters_the_anomaly_baseline():
    """`listener_observed` phát lại mỗi lần khởi động. Nếu nó vào baseline,
    Shield sẽ học "mở cổng lúc 7 giờ sáng là bình thường" — vì đó là giờ máy
    được bật, không phải giờ dịch vụ khởi động."""
    from shield.security.anomaly import BEHAVIOR_KEY_FORMATS, OBSERVED_KINDS

    assert "listener_observed" not in OBSERVED_KINDS
    assert "listener_observed" not in BEHAVIOR_KEY_FORMATS


def test_the_existing_behaviour_key_formats_are_unchanged():
    """Thêm một loại event mới KHÔNG được kích hoạt học lại cho loại cũ."""
    from shield.security.anomaly import BEHAVIOR_KEY_FORMATS

    assert BEHAVIOR_KEY_FORMATS == {
        "process_exec": 1, "process_started": 2, "listener_opened": 1,
        "service_changed": 1, "dns_servers_changed": 1, "host_seen": 1,
        "ssh_auth_success": 1, "login_success": 1,
    }


def test_a_bootstrap_event_produces_no_anomaly_alert(tmp_path):
    from shield.agent.store import Store
    from shield.security.anomaly import LocalBaselineDetector

    store = Store(tmp_path / "s.db", allow_migration=True)
    detector = LocalBaselineDetector(store, minimum_observations=1)
    event = Event(time.time(), "endpoint", "listener_observed",
                  {"protocol": "tcp4", "port": 445, "inode": "1"})
    assert detector.handle_event(event) == []


# --- cảnh báo cổng nguy hiểm lúc khởi động ---


def test_a_risky_bootstrap_port_gets_its_own_rule_and_severity():
    detector = EndpointDetector()
    alert, = detector.handle_event(Event(1.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
        "owners": [{"pid": 9, "start_ticks": "5"}], "resolution": RESOLVED}))
    assert alert.rule_id == "RISKY_LISTENER_PRESENT_AT_STARTUP"
    assert alert.severity == "info", "phải thấp hơn cảnh báo 'vừa mở' đúng một bậc"
    assert alert.subject == "tcp4:445"


def test_the_bootstrap_severity_is_one_step_below_the_live_one():
    from shield.agent.problems import SEVERITY_ORDER

    detector = EndpointDetector()
    data = {"protocol": "tcp4", "port": 445, "inode": "1"}
    live, = detector.handle_event(Event(1.0, "endpoint", "listener_opened", dict(data)))
    boot, = detector.handle_event(Event(1.0, "endpoint", "listener_observed", dict(data)))
    assert SEVERITY_ORDER[boot.severity] == SEVERITY_ORDER[live.severity] - 1
    assert boot.severity in SEVERITY_ORDER, "không được tự tạo mức mới"


def test_the_wording_never_claims_when_the_port_was_opened():
    """Shield không biết. Nói "vừa mở" hay "kẻ tấn công mở" là bịa, và một câu
    bịa trong cảnh báo an ninh là thứ người ta hành động theo."""
    detector = EndpointDetector()
    alert, = detector.handle_event(Event(1.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "port": 3389, "inode": "1"}))
    text = (alert.title + " " + alert.detail).lower()
    for forbidden in ("just opened", "newly", "new listener", "started listening",
                      "persistence", "attacker", "appeared", "vừa mở", "mới xuất hiện"):
        assert forbidden not in text, f"cảnh báo khẳng định điều không biết: {forbidden!r}"
    assert "unknown" in text


def test_only_one_alert_per_service_even_with_several_owners():
    detector = EndpointDetector()
    alerts = detector.handle_event(Event(1.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "port": 445, "inode": "1", "resolution": AMBIGUOUS,
        "owners": [{"pid": 7, "start_ticks": "1"}, {"pid": 8, "start_ticks": "2"}]}))
    assert len(alerts) == 1
    assert alerts[0].evidence["owner_identities"] == ["7:1", "8:2"]


def test_the_owner_identities_are_deterministic_whatever_the_input_order():
    detector = EndpointDetector()
    orders = ([{"pid": 9, "start_ticks": "5"}, {"pid": 8, "start_ticks": "4"}],
              [{"pid": 8, "start_ticks": "4"}, {"pid": 9, "start_ticks": "5"}])
    seen = set()
    for owners in orders:
        alert, = detector.handle_event(Event(1.0, "endpoint", "listener_observed", {
            "protocol": "tcp4", "port": 445, "owners": owners}))
        seen.add(tuple(alert.evidence["owner_identities"]))
    assert len(seen) == 1, seen


def test_a_harmless_bootstrap_port_raises_nothing():
    assert EndpointDetector().handle_event(Event(1.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "port": 22, "inode": "1"})) == []


def test_the_sensitive_port_list_is_shared_by_both_branches():
    source = (ROOT / "shield" / "agent" / "detectors" / "endpoint.py").read_text(
        encoding="utf-8")
    assert source.count("SENSITIVE_LISTENER_PORTS") >= 3, "hằng số không được dùng lại"
    assert source.count("{23, 445, 3389, 5900}") == 1, \
        "danh sách cổng nguy hiểm có nhiều hơn một bản"


# --- chống trùng qua nhiều lần khởi động ---


def test_repeated_restarts_do_not_pile_up_alert_rows(tmp_path):
    """Cơ chế chống trùng CHÍNH DANH — `(subject, rule_id)` tra thẳng bảng
    `alerts` — đã sống qua restart. Thứ thiếu chỉ là cách để detector nói ra
    nhịp của mình, và `dedupe_window_s` trên Alert là chỗ đó."""
    from shield.agent.store import Store

    store = Store(tmp_path / "s.db", allow_migration=True)
    detector = EndpointDetector()
    base = time.time()
    for restart in range(6):                       # sáu lần khởi động, cách nhau 1 giờ
        alert, = detector.handle_event(Event(base, "endpoint", "listener_observed", {
            "protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1"}))
        alert = dataclasses.replace(alert, ts=base + restart * 3600)
        store.insert_alert(alert, dedupe_window_s=alert.dedupe_window_s or 300)

    rows = store.conn.execute(
        "SELECT COUNT(*), MAX(count) FROM alerts "
        "WHERE rule_id='RISKY_LISTENER_PRESENT_AT_STARTUP'").fetchone()
    assert rows[0] == 1, f"{rows[0]} hàng alert cho một cổng không đổi"
    assert rows[1] == 6, "số lần quan sát không được ghi nhận"


def test_the_cooldown_is_long_enough_to_span_restarts():
    assert BOOTSTRAP_ALERT_COOLDOWN_S >= 86400


def test_no_second_dedupe_store_was_created():
    import ast as _ast

    for relative in ("shield/agent/detectors/endpoint.py",
                     "shield/agent/collectors/endpoint.py"):
        tree = _ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        names = {n.id for n in _ast.walk(tree) if isinstance(n, _ast.Name)}
        for forbidden in ("_last_alerted", "_seen_services", "_alerted_ports"):
            assert forbidden not in names, f"{relative}: kho chống trùng thứ hai"


# --- danh tính service: địa chỉ bind thuộc khoá ---
#
# Đo trên máy thật: 40 socket gộp thành 33 node với khoá `host:proto:port`, và
# ca tệ nhất là `udp4:5353` — `0.0.0.0` (pid 1573) và `224.0.0.251` (pid 15398)
# thành một node, hai tiến trình không liên quan trỏ vào đó như thể cùng phục
# vụ một thứ. Đó không phải mất dữ liệu, đó là một khẳng định sai.


def _service_key(**data) -> str:
    payload = {"inode": "1", "owners": [], "resolution": UNRESOLVED, **data}
    entities, _ = resolve(Event(1000.0, "endpoint", "listener_observed", payload))
    return next(e.canonical_key for e in entities if e.entity_type == "service")


def test_wildcard_and_a_specific_address_are_two_services():
    assert _service_key(protocol="udp4", ip="0.0.0.0", port=5353) != \
           _service_key(protocol="udp4", ip="224.0.0.251", port=5353)


def test_the_real_5353_collision_is_gone():
    """Ca đã đo được trên máy thật, với đúng hai chủ sở hữu khác nhau."""
    a = resolve(Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "udp4", "ip": "0.0.0.0", "port": 5353, "inode": "29716",
        "owners": [{"pid": 1573, "start_ticks": "10"}], "resolution": RESOLVED}))
    b = resolve(Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "udp4", "ip": "224.0.0.251", "port": 5353, "inode": "99985",
        "owners": [{"pid": 15398, "start_ticks": "20"}], "resolution": RESOLVED}))
    svc_a = next(e for e in a[0] if e.entity_type == "service")
    svc_b = next(e for e in b[0] if e.entity_type == "service")
    assert svc_a.canonical_key != svc_b.canonical_key
    dst_a = {e.dst_id for e in a[1] if e.relation == "listens_on"}
    dst_b = {e.dst_id for e in b[1] if e.relation == "listens_on"}
    assert dst_a and dst_b and dst_a != dst_b, "hai chủ sở hữu vẫn trỏ chung một node"


def test_the_same_binding_seen_twice_stays_one_service():
    """Multicast: cùng tiến trình tham gia một nhóm hai lần, hai inode. `inode`
    KHÔNG thuộc khoá — đưa vào sẽ xoá lịch sử quan sát mỗi lần socket được tạo
    lại."""
    assert _service_key(protocol="udp4", ip="239.255.255.250", port=3702, inode="565414") == \
           _service_key(protocol="udp4", ip="239.255.255.250", port=3702, inode="175436")


def test_several_owners_of_one_binding_share_the_service():
    _entities, edges = resolve(Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "ip": "0.0.0.0", "port": 22, "inode": "1",
        "resolution": AMBIGUOUS,
        "owners": [{"pid": 1, "start_ticks": "11"}, {"pid": 2429, "start_ticks": "568"}]}))
    listens = [e for e in edges if e.relation == "listens_on"]
    assert len(listens) == 2
    assert len({e.dst_id for e in listens}) == 1, "cùng một binding mà ra hai service"


def test_tcp_and_udp_on_the_same_address_stay_apart():
    assert _service_key(protocol="tcp4", ip="127.0.0.53", port=53) != \
           _service_key(protocol="udp4", ip="127.0.0.53", port=53)


def test_ipv4_and_ipv6_stay_apart():
    assert _service_key(protocol="tcp4", ip="0.0.0.0", port=3306) != \
           _service_key(protocol="tcp6", ip="::", port=3306)


def test_an_ipv6_key_is_deterministic_and_readable():
    """Ngoặc vuông để `local:tcp6:[::]:3306` đọc được bằng mắt. Băm thì không
    mơ hồ, nhưng con người sẽ đọc nhầm `local:tcp6:::3306`."""
    key = _service_key(protocol="tcp6", ip="::", port=3306)
    assert key == "local:tcp6:[::]:3306"
    assert _service_key(protocol="udp6", ip="ff02::c", port=3702) == \
        "local:udp6:[ff02::c]:3702"
    assert key == _service_key(protocol="tcp6", ip="::", port=3306)


def test_a_dual_stack_socket_makes_no_ipv4_shadow_node():
    """Một socket kernel = một node. Nó nhận cả IPv4 lẫn IPv6 nhưng vẫn là một
    binding; tách đôi là bịa ra một node không tồn tại."""
    entities, _ = resolve(Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "tcp6", "ip": "::", "port": 3306, "inode": "1",
        "owners": [], "resolution": UNRESOLVED}))
    services = [e for e in entities if e.entity_type == "service"]
    assert len(services) == 1
    assert "0.0.0.0" not in services[0].canonical_key


def test_an_unknown_bind_address_is_not_confused_with_the_wildcard():
    """`[]` nghĩa là "không biết bind ở đâu"; `[0.0.0.0]` nghĩa là "mọi địa chỉ
    IPv4". Gộp hai cái đó là biến một chỗ thiếu dữ liệu thành một khẳng định."""
    assert _service_key(protocol="tcp4", ip="", port=445) == "local:tcp4:[]:445"
    assert _service_key(protocol="tcp4", ip="", port=445) != \
           _service_key(protocol="tcp4", ip="0.0.0.0", port=445)


def test_bootstrap_and_live_resolve_to_the_same_canonical_key():
    payload = {"protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
               "owners": [{"pid": 7, "start_ticks": "9"}], "resolution": RESOLVED}
    keys = set()
    for kind in ("listener_observed", "listener_opened"):
        entities, _ = resolve(Event(1000.0, "endpoint", kind, dict(payload)))
        keys.add(next(e.canonical_key for e in entities if e.entity_type == "service"))
    assert len(keys) == 1


# --- dựng lại đồ thị khi định dạng khoá đổi ---


def test_dropping_a_type_removes_its_edges_first(tmp_path):
    """`graph_edges` KHÔNG có ràng buộc khoá ngoại — `PRAGMA foreign_key_list`
    trả rỗng. Không có gì ngăn cạnh trỏ tới node đã biến mất ngoài kỷ luật của
    chính hàm dọn."""
    from shield.agent.store import Store
    from shield.evidence.graph import EvidenceGraph

    store = Store(tmp_path / "s.db", allow_migration=True)
    event = Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
        "owners": [{"pid": 7, "start_ticks": "9"}], "resolution": RESOLVED})
    store.insert_event(event)
    store.graph_ingest_event(event)
    assert store.conn.execute(
        "SELECT COUNT(*) FROM graph_edges WHERE relation='listens_on'").fetchone()[0] == 1

    result = EvidenceGraph(store.conn).drop_entities_of_type("service")
    assert result["entities_removed"] == 1
    assert result["edges_removed"] >= 1

    ids = {r[0] for r in store.conn.execute("SELECT entity_id FROM graph_entities")}
    orphans = [r for r in store.conn.execute("SELECT edge_id,src_id,dst_id FROM graph_edges")
               if r[1] not in ids or r[2] not in ids]
    assert orphans == [], f"cạnh mồ côi sau khi dọn: {orphans}"


def test_dropping_a_type_touches_neither_events_nor_other_entities(tmp_path):
    """Đồ thị dựng lại được từ event; event thì không dựng lại được từ đâu cả."""
    from shield.agent.store import Store
    from shield.evidence.graph import EvidenceGraph

    store = Store(tmp_path / "s.db", allow_migration=True)
    for kind, data in (("listener_observed", {"protocol": "tcp4", "ip": "0.0.0.0",
                                              "port": 445, "inode": "1",
                                              "owners": [{"pid": 7, "start_ticks": "9"}],
                                              "resolution": RESOLVED}),
                       ("process_exec", {"pid": 7, "uid": 0, "exe": "/bin/sh",
                                         "start_ticks": "9",
                                         "process_identity": "7:9"})):
        event = Event(1000.0, "endpoint" if "listener" in kind else "kernel", kind, data)
        store.insert_event(event)
        store.graph_ingest_event(event)

    events_before = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    procs_before = store.conn.execute(
        "SELECT COUNT(*) FROM graph_entities WHERE entity_type='process'").fetchone()[0]
    EvidenceGraph(store.conn).drop_entities_of_type("service")
    assert store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events_before
    assert store.conn.execute(
        "SELECT COUNT(*) FROM graph_entities WHERE entity_type='process'"
    ).fetchone()[0] == procs_before
    assert store.conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_the_format_reconcile_rebuilds_once_then_stays_quiet(tmp_path):
    from shield.agent.store import Store
    from shield.evidence.resolver import GRAPH_KEY_FORMATS

    store = Store(tmp_path / "s.db", allow_migration=True)
    event = Event(1000.0, "endpoint", "listener_observed", {
        "protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "1",
        "owners": [{"pid": 7, "start_ticks": "9"}], "resolution": RESOLVED})
    store.insert_event(event)
    store.graph_ingest_event(event)

    first = store.reconcile_graph_key_formats(GRAPH_KEY_FORMATS)
    assert [r["entity_type"] for r in first] == ["service"]
    assert first[0]["entities_removed"] == 1
    assert store.reconcile_graph_key_formats(GRAPH_KEY_FORMATS) == [], \
        "lượt khởi động thứ hai lại xoá đồ thị"


def test_the_rebuild_is_audited(tmp_path):
    from shield.agent.store import Store
    from shield.evidence.resolver import GRAPH_KEY_FORMATS

    store = Store(tmp_path / "s.db", allow_migration=True)
    store.reconcile_graph_key_formats(GRAPH_KEY_FORMATS)
    rows = [r for r in store.recent_audit_logs(20)
            if r["action_id"] == "graph_key_format_rebuild"]
    assert len(rows) == 1
    assert rows[0]["params"]["entity_type"] == "service"
    assert rows[0]["params"]["new_format"] == GRAPH_KEY_FORMATS["service"]


def test_a_type_still_at_version_one_is_not_rebuilt(tmp_path):
    from shield.agent.store import Store

    store = Store(tmp_path / "s.db", allow_migration=True)
    event = Event(1000.0, "kernel", "process_exec",
                  {"pid": 7, "uid": 0, "exe": "/bin/sh", "start_ticks": "9",
                   "process_identity": "7:9"})
    store.insert_event(event)
    store.graph_ingest_event(event)
    before = store.conn.execute(
        "SELECT COUNT(*) FROM graph_entities WHERE entity_type='process'").fetchone()[0]
    assert store.reconcile_graph_key_formats({"process": 1}) == []
    assert store.conn.execute(
        "SELECT COUNT(*) FROM graph_entities WHERE entity_type='process'"
    ).fetchone()[0] == before


def test_the_resolver_is_still_the_only_place_that_creates_services():
    import ast as _ast

    creators = []
    for path in sorted(ROOT.glob("shield/**/*.py")):
        text = path.read_text(encoding="utf-8")
        if 'entity(\n            "service"' in text or 'entity("service"' in text:
            creators.append(str(path.relative_to(ROOT)))
    assert creators == ["shield/evidence/resolver.py"], creators
