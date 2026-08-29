"""PortscanDetector đối mặt gói tin THẬT — chạy trong network namespace.

Vì sao cần file này dù đã có bài phát lại 637.548 gói thật: bài kia chứng minh
detector xử lý đúng chuỗi event mà chúng ta ĐƯA cho nó. Không bài nào chứng
minh `conn_watch` bóc đúng cờ TCP từ một gói do kernel sinh ra.

Vì sao KHÔNG quét máy thật: quét `127.0.0.1` cho ra đúng 0 event vì hai lý do
độc lập — `local_ips()` loại `127.*` tường minh, và gói tới địa chỉ của chính
máy đi qua `lo` chứ không qua interface sniffer đang nghe.

TOPO: máy bị quét nằm TRONG namespace, máy quét nằm ở host.

    host  10.78.0.1  --- shield-scan-h <=> shield-scan-n ---  netns  10.78.0.2
    (máy quét)                                                (Shield chạy ở đây)

Chiều này KHÔNG phải tuỳ tiện. Bản trước đặt ngược lại — máy bị quét ở host —
và mọi SYN bị `ufw` của host DROP im lặng: không SYN-ACK, không cả RST, và
`connect()` hết giờ. Detector khi đó gán nhãn `syn` hoàn toàn ĐÚNG, vì trên dây
nó đúng là một cuộc quét chỉ có SYN; sai là ở bài test gọi đó là "bắt tay hoàn
tất". Namespace có bảng netfilter riêng và rỗng, nên đặt máy bị quét vào trong
đó cho ta một máy trả lời thật — mà không sửa một dòng firewall nào của host.

    sudo SHIELD_NETNS_TESTS=1 .venv/bin/python -m pytest tests/test_portscan_netns.py -v -s
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import pytest

from shield.agent.detectors.portscan import DEFAULT_PORT_THRESHOLD, DEFAULT_WINDOW_S

pytestmark = [
    pytest.mark.netns,
    pytest.mark.skipif(os.geteuid() != 0, reason="cần root để tạo network namespace"),
    pytest.mark.skipif(os.environ.get("SHIELD_NETNS_TESTS") != "1",
                       reason="đặt SHIELD_NETNS_TESTS=1 để chạy có chủ đích"),
]

NS = "shield-scan-test"
HOST_VETH = "shield-scan-h"
NS_VETH = "shield-scan-n"
SCANNER_IP = "10.78.0.1"    # host — nơi phát ra cuộc quét
VICTIM_IP = "10.78.0.2"     # namespace — nơi Shield quan sát

SCAN_PORTS = 20
OPEN_BASE = 20000
CLOSED_BASE = 30000
PACING_S = 0.03
REPO = str(Path(__file__).resolve().parent.parent)
MARKER = "SHIELD_RESULT "

# Kịch bản chạy TRONG namespace: đúng đường ống production, không mô phỏng.
HELPER = r'''
import asyncio, json, socket, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from shield.agent.bus import Bus
from shield.agent.collectors import conn_watch
from shield.agent.detectors.portscan import PortscanDetector

REPO, MODE, PORTS, IFACE, VICTIM, READY, DONE, MARKER = sys.argv[1:9]
ports = [int(p) for p in PORTS.split(",")]

async def main():
    servers = []
    if MODE == "open":
        for port in ports:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((VICTIM, port)); srv.listen(8); servers.append(srv)
    bus = Bus(max_queue_size=8192, overflow_policy="drop_oldest")
    queue = bus.subscribe()
    task = asyncio.create_task(conn_watch.sniff_loop(bus, interface=IFACE))
    try:
        await asyncio.sleep(2.5)
        Path(READY).write_text("1")
        for _ in range(600):
            if Path(DONE).exists():
                break
            await asyncio.sleep(0.1)
        await asyncio.sleep(2.5)
        kinds, alerts = {}, []
        detector = PortscanDetector(store=None)
        while not queue.empty():
            event = queue.get_nowait()
            kinds[event.kind] = kinds.get(event.kind, 0) + 1
            for alert in detector.handle_event(event):
                alerts.append({"rule_id": alert.rule_id, "subject": alert.subject,
                               "ts": alert.ts, "evidence": alert.evidence})
        print(MARKER + json.dumps({"kinds": kinds, "alerts": alerts,
                                   "bus": bus.stats()}), flush=True)
    finally:
        for srv in servers:
            try: srv.close()
            except OSError: pass
        task.cancel()
        try: await task
        except BaseException: pass

asyncio.run(main())
'''


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check)


def in_ns(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run("ip", "netns", "exec", NS, *args, check=check)


def counters(interface: str) -> tuple[int, int]:
    base = Path(f"/sys/class/net/{interface}/statistics")
    try:
        return (int((base / "tx_packets").read_text()),
                int((base / "rx_packets").read_text()))
    except OSError:
        return (0, 0)


@pytest.fixture(scope="module")
def namespace():
    run("ip", "netns", "del", NS, check=False)
    run("ip", "link", "del", HOST_VETH, check=False)
    for _ in range(50):
        if not Path(f"/sys/class/net/{HOST_VETH}").exists():
            break
        time.sleep(0.1)
    run("ip", "netns", "add", NS)
    try:
        run("ip", "link", "add", HOST_VETH, "type", "veth", "peer", "name", NS_VETH)
        run("ip", "link", "set", NS_VETH, "netns", NS)
        run("ip", "addr", "add", f"{SCANNER_IP}/24", "dev", HOST_VETH)
        run("ip", "link", "set", HOST_VETH, "up")
        in_ns("ip", "addr", "add", f"{VICTIM_IP}/24", "dev", NS_VETH)
        in_ns("ip", "link", "set", NS_VETH, "up")
        in_ns("ip", "link", "set", "lo", "up")
        for _ in range(50):
            if Path(f"/sys/class/net/{HOST_VETH}/operstate").exists():
                break
            time.sleep(0.1)
        yield
    finally:
        run("ip", "netns", "del", NS, check=False)
        run("ip", "link", "del", HOST_VETH, check=False)


def scan_from_host(ports, hold_s: float = 0.0) -> Counter:
    """`connect()` thường từ host tới máy trong namespace. Không dựng gói thô.

    Cổng ĐÓNG: SYN rồi nhận RST — phía quét không gửi ACK, chữ ký SYN-scan.
    Cổng MỞ:   SYN + SYN-ACK + ACK — chữ ký connect-scan.
    """
    outcome: Counter = Counter()
    for port in ports:
        sock = socket.socket()
        sock.settimeout(0.4)
        try:
            sock.connect((VICTIM_IP, port))
            outcome["connected"] += 1
            if hold_s:
                time.sleep(hold_s)
        except OSError as exc:
            outcome[f"{type(exc).__name__}:{getattr(exc, 'errno', '')}"] += 1
        finally:
            sock.close()
        time.sleep(PACING_S)
    return outcome


class FlagCensus:
    """Cờ TCP thật sự trên dây, CẢ HAI CHIỀU.

    Bản trước chỉ đếm một chiều, nên `{'S': 5}` không phân biệt được "bắt tay
    xong nhưng ACK bị gộp" với "máy bị quét không hề trả lời". Một phép đo
    không phân biệt được hai giả thuyết thì chưa phải phép đo.
    """

    def __init__(self) -> None:
        self.to_victim: Counter = Counter()
        self.to_scanner: Counter = Counter()
        self._sniffer = None

    def __enter__(self):
        from scapy.all import IP, TCP, AsyncSniffer

        def record(pkt):
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return
            flags = str(pkt[TCP].flags)
            if pkt[IP].dst == VICTIM_IP:
                self.to_victim[flags] += 1
            elif pkt[IP].dst == SCANNER_IP:
                self.to_scanner[flags] += 1

        self._sniffer = AsyncSniffer(iface=HOST_VETH, filter="tcp", prn=record, store=False)
        self._sniffer.start()
        time.sleep(1.0)
        return self

    def __exit__(self, *exc):
        with contextlib.suppress(Exception):
            self._sniffer.stop()
        return False


def observe_scan(ports, *, listeners: bool, hold_s: float = 0.0) -> dict:
    """Chạy Shield TRONG namespace, quét từ host, trả về những gì Shield thấy."""
    with tempfile.TemporaryDirectory() as tmp:
        helper = Path(tmp) / "victim.py"
        helper.write_text(HELPER)
        ready, done = Path(tmp) / "ready", Path(tmp) / "done"
        proc = subprocess.Popen(
            ["ip", "netns", "exec", NS, sys.executable, str(helper), REPO,
             "open" if listeners else "closed", ",".join(str(p) for p in ports),
             NS_VETH, VICTIM_IP, str(ready), str(done), MARKER],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(300):
                if ready.exists() or proc.poll() is not None:
                    break
                time.sleep(0.1)
            assert ready.exists(), "Shield trong namespace không khởi động được"
            started = time.time()
            with FlagCensus() as census:
                outcome = scan_from_host(ports, hold_s)
                time.sleep(1.0)
                to_victim = Counter(census.to_victim)
                to_scanner = Counter(census.to_scanner)
            done.write_text("1")
            stdout, stderr = proc.communicate(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
        line = next((ln for ln in stdout.splitlines() if ln.startswith(MARKER)), None)
        assert line, f"không có kết quả từ namespace\nstdout={stdout}\nstderr={stderr[-2000:]}"
        result = json.loads(line[len(MARKER):])
        result.update({"outcome": dict(outcome), "to_victim": dict(to_victim),
                       "to_scanner": dict(to_scanner), "started": started})
        return result


def report(label: str, result: dict) -> None:
    print(f"\n  {label}")
    print(f"    kết quả connect()   : {result['outcome']}")
    print(f"    quét -> máy bị quét : {result['to_victim']}")
    print(f"    máy bị quét -> quét : {result['to_scanner']}")
    print(f"    event Shield thấy   : {result['kinds']}")
    if result["alerts"]:
        evidence = result["alerts"][-1]["evidence"]
        print(f"    nhãn: {evidence['scan_type_key']} | ack_source={evidence['ack_source']} "
              f"| acked={len(evidence['acked_ports_matched'])} cổng "
              f"| {len(result['alerts'])} cảnh báo")


# --- điều kiện tiên quyết ---


def test_the_namespace_has_no_route_off_the_veth(namespace):
    routes = in_ns("ip", "route", "show").stdout
    assert "10.78.0.0/24" in routes
    assert "default" not in routes, f"namespace có đường ra ngoài: {routes}"


def test_the_victim_address_is_reachable_only_through_the_veth(namespace):
    route = run("ip", "route", "get", VICTIM_IP).stdout
    assert HOST_VETH in route, route
    assert "wlo1" not in route, f"đường tới máy bị quét đi qua LAN: {route}"


def test_the_detector_thresholds_are_read_from_the_real_code():
    assert DEFAULT_PORT_THRESHOLD == 15
    assert DEFAULT_WINDOW_S == 10.0
    assert SCAN_PORTS > DEFAULT_PORT_THRESHOLD
    assert SCAN_PORTS * PACING_S < DEFAULT_WINDOW_S


def test_the_victim_actually_answers(namespace):
    """Điều kiện tiên quyết, và là bài học của lần chạy trước.

    Nếu máy bị quét không trả lời gì thì mọi cuộc quét đều là SYN-scan trên
    dây, và một bài test gọi đó là "bắt tay hoàn tất" sẽ đổ lỗi cho detector vì
    một chuyện thuộc về môi trường.
    """
    result = observe_scan([OPEN_BASE], listeners=True, hold_s=0.1)
    report("một cổng MỞ", result)
    assert result["outcome"].get("connected") == 1, (
        "máy bị quét không trả lời — kiểm firewall của namespace: "
        f"{result['outcome']}")
    assert result["to_scanner"], "không gói nào quay về từ máy bị quét"


# --- đo cờ thật trên dây ---


def test_what_flags_a_completed_handshake_actually_puts_on_the_wire(namespace):
    ports = list(range(OPEN_BASE, OPEN_BASE + 5))
    immediate = observe_scan(ports, listeners=True, hold_s=0.0)
    held = observe_scan(ports, listeners=True, hold_s=0.25)
    report("đóng ngay", immediate)
    report("giữ 0,25s", held)
    assert immediate["to_victim"].get("S", 0) >= len(ports)
    assert immediate["to_scanner"], "không có gì quay về"


# --- case A: connect-scan ---


def test_a_real_connect_scan_is_detected(namespace):
    ports = list(range(OPEN_BASE, OPEN_BASE + SCAN_PORTS))
    result = observe_scan(ports, listeners=True, hold_s=0.05)
    report("connect-scan 20 cổng MỞ", result)
    assert result["kinds"].get("tcp_syn", 0) >= SCAN_PORTS, result["kinds"]
    assert result["alerts"], "20 cổng trong 1,6 giây mà không có cảnh báo"
    alert = result["alerts"][-1]
    assert alert["rule_id"] == "SCAN_PORTSCAN"
    assert alert["subject"] == SCANNER_IP
    assert alert["evidence"]["src_ip"] == SCANNER_IP
    detected = set(alert["evidence"]["ports"])
    assert detected <= set(ports), f"cổng lạ: {detected - set(ports)}"
    assert len(detected) > DEFAULT_PORT_THRESHOLD
    assert alert["ts"] - result["started"] < DEFAULT_WINDOW_S * 3
    assert result["bus"]["dropped"] == 0 and result["bus"]["backpressure_count"] == 0


def test_a_completed_handshake_is_labelled_connect(namespace):
    """Nếu bài này đỏ TRONG KHI `connected == 20`, đó là phát hiện thật về
    detector — không phải lý do để nới bài test."""
    ports = list(range(OPEN_BASE, OPEN_BASE + SCAN_PORTS))
    result = observe_scan(ports, listeners=True, hold_s=0.05)
    report("nhãn của connect-scan", result)
    assert result["outcome"].get("connected") == SCAN_PORTS, (
        "bắt tay không hoàn tất — bài này không nói gì về detector: "
        f"{result['outcome']}")
    assert result["alerts"]
    assert result["alerts"][-1]["evidence"]["scan_type_key"] == "connect", \
        result["alerts"][-1]["evidence"]
    assert result["alerts"][-1]["evidence"]["acked_ports_matched"]


# --- case B: SYN-scan ---


def test_a_real_syn_scan_is_detected_and_labelled_syn(namespace):
    ports = list(range(CLOSED_BASE, CLOSED_BASE + SCAN_PORTS))
    result = observe_scan(ports, listeners=False)
    report("SYN-scan 20 cổng ĐÓNG", result)
    assert result["outcome"].get("connected", 0) == 0, result["outcome"]
    assert result["kinds"].get("tcp_syn", 0) >= SCAN_PORTS, result["kinds"]
    assert result["alerts"]
    alert = result["alerts"][-1]
    assert alert["subject"] == SCANNER_IP
    assert alert["evidence"]["scan_type_key"] == "syn", alert["evidence"]
    assert alert["evidence"]["acked_ports_matched"] == []
    assert set(alert["evidence"]["ports"]) <= set(ports)
    assert result["bus"]["dropped"] == 0


# --- cô lập và sức khoẻ ---


def test_the_scan_traffic_goes_through_the_veth(namespace):
    ports = list(range(CLOSED_BASE, CLOSED_BASE + SCAN_PORTS))
    before = counters(HOST_VETH)
    scan_from_host(ports)
    after = counters(HOST_VETH)
    assert after[0] - before[0] >= SCAN_PORTS, \
        f"cuộc quét không đi qua veth: tx +{after[0] - before[0]}"


def test_one_scan_does_not_produce_an_alert_flood(namespace):
    ports = list(range(CLOSED_BASE, CLOSED_BASE + SCAN_PORTS))
    result = observe_scan(ports, listeners=False)
    assert result["alerts"]
    assert {a["subject"] for a in result["alerts"]} == {SCANNER_IP}
    assert {a["rule_id"] for a in result["alerts"]} == {"SCAN_PORTSCAN"}
    assert len(result["alerts"]) <= SCAN_PORTS - DEFAULT_PORT_THRESHOLD, \
        f"{len(result['alerts'])} cảnh báo cho một cuộc quét {SCAN_PORTS} cổng"
