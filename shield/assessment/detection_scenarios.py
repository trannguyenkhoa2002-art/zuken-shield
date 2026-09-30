"""20 kịch bản xác thực khả năng PHÁT HIỆN — chạy qua đường ống thật của agent.

Mỗi kịch bản mô tả một hành vi tấn công đã biết, dựng đúng chuỗi `Event` mà một
collector thật phát ra cho hành vi đó (kind/data lấy đúng từ mã collector), rồi
cho chạy qua `run_event_consumer` + `run_alert_consumer` — tức detector thật,
chấm điểm Risk/Evidence Confidence, vùng xám, correlation và incident — trên một
`Store` thật. Không mô phỏng detector, không viết cứng kết quả.

Đây là kiểm thử PHÒNG THỦ: đo xem IDS có phát hiện đúng thứ nó tuyên bố hay
không. Nó KHÔNG thực hiện tấn công thật; nó phát lại telemetry mà một cuộc tấn
công sẽ để lại. Đường packet/journal end-to-end (nmap thật, sshd thật) đã được
`tests/test_portscan_netns.py` và `tests/test_response_e2e_netns.py` chứng minh
riêng trong container privileged.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from typing import cast

from shield.agent.bus import Bus
from shield.agent.detectors.dns import BASELINE_DNS_SERVERS, DnsDetector
from shield.agent.detectors.endpoint import EndpointDetector
from shield.agent.detectors.local_log import LocalLogDetector
from shield.agent.detectors.mitm import (BASELINE_DHCP_IP, BASELINE_GW_IP, BASELINE_GW_MAC,
                                         MitmDetector)
from shield.agent.detectors.portscan import PortscanDetector
from shield.agent.detectors.unknown_device import UnknownDeviceDetector
from shield.agent.store import Store
from shield.common.models import Event

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
ATTACKER = "198.51.100.66"          # RFC 5737, không bao giờ là máy thật
ATTACKER_MAC = "aa:bb:cc:00:00:66"


def _e(kind: str, data: dict, source: str = "kernel", ts: float | None = None) -> Event:
    return Event(ts or time.time(), source, kind, data)


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    technique: str                   # MITRE ATT&CK
    attacker_action: str             # điều kẻ tấn công làm để sinh telemetry này
    events: Callable[[], list[Event]]
    expect_alerts: tuple[str, ...] = ()      # rule_id BẮT BUỘC phải nổ
    expect_incident: str = ""                # correlation_id của incident mong đợi
    expect_gray_zone: str = ""               # kind vùng xám mong đợi (below_threshold...)
    seed: Callable[[Store], None] = field(default=lambda store: None)


def _ssh_fail(n: int) -> list[Event]:
    return [_e("ssh_failed_password", {"src_ip": ATTACKER, "message": f"Failed password #{i}"},
               "journal") for i in range(n)]


def _syn(n: int) -> list[Event]:
    return [_e("tcp_syn", {"src_ip": ATTACKER, "dst_port": 1000 + i}, "conn_watch") for i in range(n)]


def _seed_gateway(store: Store) -> None:
    store.set_baseline(BASELINE_GW_IP, "192.0.2.1")
    store.set_baseline(BASELINE_GW_MAC, "00:00:5e:00:53:01")


def _seed_dns(store: Store) -> None:
    store.set_baseline(BASELINE_DNS_SERVERS, "192.0.2.1")


def _seed_dhcp(store: Store) -> None:
    store.set_baseline(BASELINE_DHCP_IP, "192.0.2.1")


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("ssh-bruteforce", "SSH brute force", "T1110",
             "5 lần thử mật khẩu SSH sai từ một nguồn trong cửa sổ",
             lambda: _ssh_fail(6), expect_alerts=("LOCAL_SSH_BRUTEFORCE",)),
    Scenario("ssh-near-miss", "SSH thử sai gần ngưỡng", "T1110",
             "3 lần sai — dưới ngưỡng phát hiện, phải vào vùng xám chứ không im lặng",
             lambda: _ssh_fail(3), expect_gray_zone="below_threshold"),
    Scenario("sudo-failure", "sudo thất bại", "T1548",
             "Nhập sai mật khẩu sudo (thử leo thang quyền)",
             lambda: [_e("sudo_failed", {"user": "mallory", "message": "authentication failure"}, "journal")],
             expect_alerts=("LOCAL_SUDO_FAIL",)),
    Scenario("usb-new-journal", "Cắm USB (kernel log)", "T1200",
             "Cắm thiết bị USB lạ — kernel ghi 'New USB device found'",
             lambda: [_e("usb_new", {"message": "New USB device found, idVendor=1234"}, "journal")],
             expect_alerts=("LOCAL_NEW_USB",)),
    Scenario("promisc-mode", "Interface vào promiscuous mode", "T1040",
             "Một công cụ nghe lén bật promiscuous trên interface không phải của Shield",
             lambda: [_e("promisc_mode", {"interface": "eth9", "message": "device entered promiscuous mode"}, "journal")],
             expect_alerts=("LOCAL_PROMISC_MODE",)),
    Scenario("suspicious-exec", "Tiến trình chạy từ /tmp", "T1059",
             "Chạy payload từ thư mục tạm (/tmp) — vị trí điển hình của mã độc",
             lambda: [_e("process_exec", {"pid": 4242, "exe": "/tmp/.x/payload", "comm": "payload"}, "auditd")],
             expect_alerts=("ENDPOINT_SUSPICIOUS_EXEC_PATH",)),
    Scenario("deleted-executable", "Chạy file thực thi đã bị xoá", "T1070.004",
             "Tiến trình chạy từ một file đã unlink khỏi đĩa (che dấu vết)",
             lambda: [_e("process_started", {"pid": 5150, "exe": "/usr/sbin/sshd (deleted)"}, "endpoint")],
             expect_alerts=("ENDPOINT_DELETED_EXECUTABLE",)),
    Scenario("security-config-change", "Sửa file cấu hình bảo mật", "T1098",
             "Sửa /etc/sudoers hoặc /etc/passwd (auditd)",
             lambda: [_e("security_file_changed", {"path": "/etc/sudoers", "pid": 6001, "exe": "/usr/bin/vim"}, "auditd")],
             expect_alerts=("ENDPOINT_SECURITY_CONFIG_CHANGED",)),
    Scenario("fim-modified", "File toàn vẹn thay đổi", "T1565.001",
             "Sửa một file đang được giám sát toàn vẹn (/etc/hosts)",
             lambda: [_e("file_modified", {"after": {"path": "/etc/hosts"}, "path": "/etc/hosts"}, "fim")],
             expect_alerts=("FILE_INTEGRITY_CHANGED",)),
    Scenario("sensitive-listener", "Mở cổng SMB (445)", "T1571",
             "Mở listener SMB (445) — detector endpoint coi là dịch vụ nhạy cảm",
             lambda: [_e("listener_opened", {"port": 445, "protocol": "tcp", "ip": "0.0.0.0", "pid": 7000}, "endpoint")],
             expect_alerts=("ENDPOINT_SENSITIVE_LISTENER_OPENED",)),
    Scenario("backdoor-listener", "Mở cổng backdoor (4444)", "T1571",
             "Mở listener trên cổng 4444 (Metasploit mặc định) — rule pack endpoint",
             lambda: [_e("listener_opened", {"port": 4444, "protocol": "tcp", "ip": "0.0.0.0"}, "endpoint")],
             expect_alerts=("ENDPOINT_LISTENER_ON_REMOTE_ACCESS_PORT",)),
    Scenario("usb-storage", "Gắn ổ USB storage", "T1200",
             "Gắn thiết bị lưu trữ USB — rule pack endpoint",
             lambda: [_e("usb_device_added", {"vendor": "SanDisk", "product": "Cruzer", "vendor_id": "0781"}, "endpoint")],
             expect_alerts=("ENDPOINT_USB_STORAGE_ATTACHED",)),
    Scenario("ssh-root-login", "Đăng nhập SSH bằng root", "T1078",
             "Đăng nhập SSH thành công bằng tài khoản root",
             lambda: [_e("ssh_auth_success", {"user": "root", "ip": ATTACKER}, "journal")],
             expect_alerts=("SSH_ROOT_LOGIN_SUCCEEDED",)),
    Scenario("port-scan", "Quét cổng (16 cổng)", "T1046",
             "Quét 16 cổng khác nhau từ một nguồn trong cửa sổ",
             lambda: _syn(16), expect_alerts=("SCAN_PORTSCAN",)),
    Scenario("port-scan-near-miss", "Quét cổng gần ngưỡng (8 cổng)", "T1046",
             "Quét 8 cổng — dưới ngưỡng, phải vào vùng xám",
             lambda: _syn(8), expect_gray_zone="below_threshold"),
    Scenario("arp-conflict", "Xung đột ARP (ARP spoofing)", "T1557.002",
             "Một IP bị hai MAC khác nhau claim trong cửa sổ 60s",
             lambda: [_e("arp_reply", {"ip": "192.0.2.50", "mac": "00:00:5e:00:53:aa"}, "arp_sniffer"),
                      _e("arp_reply", {"ip": "192.0.2.50", "mac": ATTACKER_MAC}, "arp_sniffer")],
             expect_alerts=("MITM_ARP_CONFLICT",)),
    Scenario("gateway-mac-changed", "MAC gateway đổi (MITM)", "T1557",
             "Gateway trả lời ARP bằng một MAC khác baseline",
             lambda: [_e("arp_reply", {"ip": "192.0.2.1", "mac": ATTACKER_MAC}, "arp_sniffer")],
             expect_alerts=("MITM_GATEWAY_MAC_CHANGED",), seed=_seed_gateway),
    Scenario("rogue-dhcp", "DHCP server lạ", "T1557",
             "Một DHCP server lạ phát OFFER (rogue DHCP để MITM)",
             lambda: [_e("dhcp_offer", {"server_ip": "192.0.2.77"}, "arp_sniffer")],
             expect_alerts=("MITM_ROGUE_DHCP",), seed=_seed_dhcp),
    Scenario("dns-resolver-changed", "DNS resolver bị đổi", "T1557",
             "Resolver DNS của máy bị đổi so với baseline (rogue DHCP/malware)",
             lambda: [_e("dns_resolvers", {"servers": ["198.51.100.99"]}, "dns_monitor")],
             expect_alerts=("DNS_RESOLVER_CHANGED",), seed=_seed_dns),
    Scenario("recon-then-ssh", "Trinh sát rồi tấn công SSH (đa bước)", "T1046+T1110",
             "Cùng một nguồn quét cổng RỒI brute force SSH — chuỗi tấn công",
             lambda: _syn(16) + _ssh_fail(6),
             expect_alerts=("SCAN_PORTSCAN", "LOCAL_SSH_BRUTEFORCE"),
             expect_incident="CORRELATED_RECON_AND_SSH_ATTACK"),
)


class _Ipc:
    def __init__(self) -> None:
        self.broadcasts: list[tuple[str, dict]] = []

    async def broadcast(self, kind: str, data: dict) -> None:
        self.broadcasts.append((kind, data))

    async def send_to(self, client_id, kind, data) -> bool:  # noqa: ANN001
        return True

    def has_clients(self) -> bool:
        return False


def _detectors(store: Store) -> list:
    from shield.security.rules import RuleDetector

    return [
        UnknownDeviceDetector(store),
        MitmDetector(store),
        PortscanDetector(store),
        LocalLogDetector(store, own_interfaces=set()),
        DnsDetector(store),
        EndpointDetector(),
        RuleDetector.from_directory(RULES_DIR, None),
    ]


async def _run(scenario: Scenario, store: Store) -> dict:
    from shield.agent import notifier
    from shield.agent.__main__ import run_alert_consumer, run_event_consumer
    from shield.security.gray_zone import GrayZoneStore

    notifier.set_desktop_relay(None)
    scenario.seed(store)
    event_bus: Bus[Event] = Bus()
    alert_bus: Bus = Bus()
    ipc = cast("object", _Ipc())   # _Ipc dựng đủ broadcast/send_to/has_clients cho pipeline
    tasks = [
        asyncio.create_task(run_event_consumer(event_bus, alert_bus, store, _detectors(store), ipc)),  # type: ignore[arg-type]
        asyncio.create_task(run_alert_consumer(alert_bus, store, ipc)),  # type: ignore[arg-type]
    ]
    await asyncio.sleep(0)
    try:
        for event in scenario.events():
            await event_bus.publish(event)
        # Đợi cả hai hàng đợi rút hết: mỗi subscriber có queue riêng.
        for _ in range(400):
            await asyncio.sleep(0.01)
            if all(q.empty() for q in event_bus._subscribers) and \
               all(q.empty() for q in alert_bus._subscribers):
                break
        await asyncio.sleep(0.15)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    alerts = store.recent_alerts(limit=200)
    incidents = store.list_incidents(limit=50)
    gray = GrayZoneStore(store.conn).entries(state="open", limit=200)
    return {"alerts": alerts, "incidents": incidents, "gray_zone": gray}


def run_scenario(scenario: Scenario, db_path: Path) -> dict:
    """Chạy một kịch bản, trả về kết quả và verdict đối chiếu với kỳ vọng."""
    store = Store(db_path)
    try:
        outcome = asyncio.run(_run(scenario, store))
    finally:
        store.close()
    fired = {a["rule_id"] for a in outcome["alerts"]}
    incident_ids = {str(i.get("correlation_id", "")) for i in outcome["incidents"]}
    gray_kinds = {g["kind"] for g in outcome["gray_zone"]}
    missing = [r for r in scenario.expect_alerts if r not in fired]
    incident_ok = (not scenario.expect_incident) or scenario.expect_incident in incident_ids
    gray_ok = (not scenario.expect_gray_zone) or scenario.expect_gray_zone in gray_kinds
    detected = {a["rule_id"]: {"severity": a["severity"], "risk": a.get("risk_score"),
                               "evidence_confidence": a.get("evidence_confidence")}
                for a in outcome["alerts"]}
    return {
        "id": scenario.id, "title": scenario.title, "technique": scenario.technique,
        "attacker_action": scenario.attacker_action,
        "expected_alerts": list(scenario.expect_alerts),
        "expected_incident": scenario.expect_incident,
        "expected_gray_zone": scenario.expect_gray_zone,
        "detected_alerts": detected,
        "incidents": sorted(incident_ids - {""}),
        "gray_zone_kinds": sorted(gray_kinds),
        "passed": not missing and incident_ok and gray_ok,
        "missing_alerts": missing,
        "incident_ok": incident_ok, "gray_zone_ok": gray_ok,
    }
