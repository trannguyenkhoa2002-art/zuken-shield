"""Feed Event giả vào từng detector, assert đúng Alert — không cần mạng thật,
không cần root, không cần scapy. Đây là bộ test đáng lẽ bắt được bug DHCP
option (arp_sniffer) trước khi nó crash thật trên máy người dùng.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shield.agent.detectors.local_log import LocalLogDetector
from shield.agent.detectors.mitm import BASELINE_DHCP_IP, BASELINE_GW_IP, BASELINE_GW_MAC, MitmDetector
from shield.agent.detectors.portscan import PortscanDetector
from shield.agent.detectors.unknown_device import UnknownDeviceDetector
from shield.agent.store import Store
from shield.common.models import Event, now


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(path=tmp_path / "test.db")
    yield s
    s.close()


# --- MitmDetector ---


def test_mitm_gateway_mac_changed(store: Store) -> None:
    store.set_baseline(BASELINE_GW_IP, "192.168.1.1")
    store.set_baseline(BASELINE_GW_MAC, "aa:bb:cc:dd:ee:ff")
    detector = MitmDetector(store)

    ev = Event(ts=now(), source="arp_sniffer", kind="arp_reply",
               data={"ip": "192.168.1.1", "mac": "11:22:33:44:55:66"})
    alerts = detector.handle_event(ev)

    assert any(a.rule_id == "MITM_GATEWAY_MAC_CHANGED" for a in alerts)
    changed = next(a for a in alerts if a.rule_id == "MITM_GATEWAY_MAC_CHANGED")
    assert changed.severity == "critical"
    assert changed.subject == "192.168.1.1"
    assert "pin_gateway_arp" in changed.playbook


def test_mitm_gateway_mac_unchanged_no_alert(store: Store) -> None:
    store.set_baseline(BASELINE_GW_IP, "192.168.1.1")
    store.set_baseline(BASELINE_GW_MAC, "aa:bb:cc:dd:ee:ff")
    detector = MitmDetector(store)

    ev = Event(ts=now(), source="arp_sniffer", kind="arp_reply",
               data={"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"})  # hoa/thường khác nhau
    alerts = detector.handle_event(ev)

    assert not any(a.rule_id == "MITM_GATEWAY_MAC_CHANGED" for a in alerts)


def test_mitm_no_baseline_does_not_crash(store: Store) -> None:
    """Chưa set_gateway_baseline -> không alert, không raise, chỉ log 1 lần."""
    detector = MitmDetector(store)
    ev = Event(ts=now(), source="arp_sniffer", kind="arp_reply",
               data={"ip": "192.168.1.1", "mac": "11:22:33:44:55:66"})
    alerts = detector.handle_event(ev)
    assert alerts == []


def test_mitm_arp_conflict(store: Store) -> None:
    detector = MitmDetector(store)
    ip = "192.168.1.50"
    detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="arp_reply",
                                 data={"ip": ip, "mac": "11:11:11:11:11:11"}))
    alerts = detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="arp_reply",
                                          data={"ip": ip, "mac": "22:22:22:22:22:22"}))

    conflict = [a for a in alerts if a.rule_id == "MITM_ARP_CONFLICT"]
    assert len(conflict) == 1
    assert conflict[0].severity == "critical"
    assert set(conflict[0].evidence["macs"]) == {"11:11:11:11:11:11", "22:22:22:22:22:22"}


def test_mitm_gratuitous_arp_flood(store: Store) -> None:
    detector = MitmDetector(store)
    alerts = []
    for _ in range(25):  # > GRATUITOUS_ARP_THRESHOLD (20)
        alerts = detector.handle_event(Event(
            ts=now(), source="arp_sniffer", kind="arp_gratuitous",
            data={"ip": "192.168.1.99", "mac": "de:ad:be:ef:00:01"},
        ))
    assert any(a.rule_id == "NET_GRATUITOUS_ARP_FLOOD" for a in alerts)


def test_mitm_rogue_dhcp(store: Store) -> None:
    detector = MitmDetector(store)
    # Lần đầu: học baseline, không alert.
    first = detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="dhcp_offer",
                                         data={"server_ip": "192.168.1.1"}))
    assert first == []
    assert store.get_baseline(BASELINE_DHCP_IP) == "192.168.1.1"

    # DHCP server khác baseline -> alert critical.
    alerts = detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="dhcp_offer",
                                          data={"server_ip": "10.0.0.99"}))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "MITM_ROGUE_DHCP"
    assert alerts[0].severity == "critical"


def test_mitm_icmp_redirect(store: Store) -> None:
    detector = MitmDetector(store)
    alerts = detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="icmp_redirect",
                                          data={"src_ip": "192.168.1.1"}))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "MITM_ICMP_REDIRECT"


def test_mitm_ndp_conflict(store: Store) -> None:
    detector = MitmDetector(store)
    ip6 = "fe80::1"
    detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="ndp_advertisement",
                                 data={"ip": ip6, "mac": "11:11:11:11:11:11"}))
    alerts = detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="ndp_advertisement",
                                          data={"ip": ip6, "mac": "22:22:22:22:22:22"}))

    conflict = [a for a in alerts if a.rule_id == "MITM_NDP_CONFLICT"]
    assert len(conflict) == 1
    assert conflict[0].severity == "critical"
    assert conflict[0].subject == ip6
    assert set(conflict[0].evidence["macs"]) == {"11:11:11:11:11:11", "22:22:22:22:22:22"}


def test_mitm_ndp_single_mac_no_alert(store: Store) -> None:
    detector = MitmDetector(store)
    alerts = detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="ndp_advertisement",
                                          data={"ip": "fe80::1", "mac": "11:11:11:11:11:11"}))
    assert alerts == []


def test_mitm_cleanup_removes_stale_ip_keys(store: Store) -> None:
    """Rò rỉ bộ nhớ đã sửa: IP ngừng gửi ARP phải bị dọn khỏi _ip_claims."""
    from shield.agent.detectors import mitm as mitm_mod

    detector = MitmDetector(store)
    detector.handle_event(Event(ts=now(), source="arp_sniffer", kind="arp_reply",
                                 data={"ip": "192.168.1.50", "mac": "11:11:11:11:11:11"}))
    assert "192.168.1.50" in detector._ip_claims

    # Giả lập thời gian trôi qua quá cửa sổ + chu kỳ dọn, rồi trigger cleanup
    # bằng 1 event khác (không liên quan IP cũ).
    future_ts = now() + mitm_mod.ARP_CONFLICT_WINDOW_S + mitm_mod.CLEANUP_INTERVAL_S + 10
    detector._cleanup_stale(future_ts)
    assert "192.168.1.50" not in detector._ip_claims


# --- PortscanDetector ---


def test_portscan_triggers_over_threshold(store: Store) -> None:
    detector = PortscanDetector(store, port_threshold=5, window_s=10.0)
    alerts = []
    for port in range(1, 8):  # 7 port khác nhau > threshold 5
        alerts = detector.handle_event(Event(
            ts=now(), source="conn_watch", kind="tcp_syn",
            data={"src_ip": "192.168.1.77", "dst_port": port},
        ))
    assert any(a.rule_id == "SCAN_PORTSCAN" for a in alerts)
    alert = next(a for a in alerts if a.rule_id == "SCAN_PORTSCAN")
    assert alert.evidence["scan_type_key"] == "syn"  # chưa có ACK nào


def test_portscan_under_threshold_no_alert(store: Store) -> None:
    detector = PortscanDetector(store, port_threshold=15, window_s=10.0)
    alerts = []
    for port in range(1, 5):
        alerts = detector.handle_event(Event(
            ts=now(), source="conn_watch", kind="tcp_syn",
            data={"src_ip": "192.168.1.77", "dst_port": port},
        ))
    assert alerts == []


def test_portscan_classifies_connect_scan_when_acked(store: Store) -> None:
    detector = PortscanDetector(store, port_threshold=3, window_s=10.0)
    detector.handle_event(Event(ts=now(), source="conn_watch", kind="tcp_ack",
                                 data={"src_ip": "192.168.1.77", "dst_port": 22}))
    alerts = []
    for port in [22, 23, 24, 25]:
        alerts = detector.handle_event(Event(
            ts=now(), source="conn_watch", kind="tcp_syn",
            data={"src_ip": "192.168.1.77", "dst_port": port},
        ))
    alert = next(a for a in alerts if a.rule_id == "SCAN_PORTSCAN")
    assert alert.evidence["scan_type_key"] == "connect"


def test_portscan_cleanup_removes_stale_keys(store: Store) -> None:
    from shield.agent.detectors import portscan as portscan_mod

    detector = PortscanDetector(store, port_threshold=15, window_s=10.0)
    detector.handle_event(Event(ts=now(), source="conn_watch", kind="tcp_syn",
                                 data={"src_ip": "192.168.1.77", "dst_port": 80}))
    detector.handle_event(Event(ts=now(), source="conn_watch", kind="tcp_ack",
                                 data={"src_ip": "192.168.1.77", "dst_port": 80}))
    assert "192.168.1.77" in detector._syn_events
    assert "192.168.1.77" in detector._acked_ports

    future_ts = now() + portscan_mod.ACK_RETENTION_S + portscan_mod.CLEANUP_INTERVAL_S + 10
    detector._cleanup_stale(future_ts)
    assert "192.168.1.77" not in detector._syn_events
    assert "192.168.1.77" not in detector._acked_ports


# --- UnknownDeviceDetector ---


def test_unknown_device_new_alert(store: Store) -> None:
    detector = UnknownDeviceDetector(store)
    alerts = detector.handle_event(Event(
        ts=now(), source="discovery", kind="host_seen",
        data={"mac": "00:11:22:33:44:55", "ip": "192.168.1.60", "vendor_hint": "Acme"},
    ))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "DEVICE_NEW"
    assert alerts[0].subject == "00:11:22:33:44:55"


def test_unknown_device_randomized_mac_grouped(store: Store) -> None:
    detector = UnknownDeviceDetector(store)
    # Bit locally-administered: octet đầu 0x02 (0b10).
    alerts = detector.handle_event(Event(
        ts=now(), source="discovery", kind="host_seen",
        data={"mac": "02:11:22:33:44:55", "ip": "192.168.1.61"},
    ))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "DEVICE_MAC_RANDOMIZED"
    assert alerts[0].subject == "randomized-mac-pool"


def test_unknown_device_trusted_no_alert(store: Store) -> None:
    detector = UnknownDeviceDetector(store)
    store.add_trusted("00:11:22:33:44:66")
    alerts = detector.handle_event(Event(
        ts=now(), source="discovery", kind="host_seen",
        data={"mac": "00:11:22:33:44:66", "ip": "192.168.1.62"},
    ))
    assert alerts == []


def test_unknown_device_seen_twice_no_duplicate_alert(store: Store) -> None:
    detector = UnknownDeviceDetector(store)
    ev = Event(ts=now(), source="discovery", kind="host_seen",
               data={"mac": "00:11:22:33:44:77", "ip": "192.168.1.63"})
    first = detector.handle_event(ev)
    second = detector.handle_event(ev)
    assert len(first) == 1
    assert second == []  # đã thấy rồi, không phải "mới" nữa


# --- LocalLogDetector ---


def test_local_log_ssh_bruteforce_threshold(store: Store) -> None:
    detector = LocalLogDetector(store)
    alerts = []
    for _ in range(5):  # == SSH_BRUTEFORCE_THRESHOLD
        alerts = detector.handle_event(Event(
            ts=now(), source="journal", kind="ssh_failed_password",
            data={"src_ip": "203.0.113.5", "message": "Failed password"},
        ))
    assert any(a.rule_id == "LOCAL_SSH_BRUTEFORCE" for a in alerts)


def test_local_log_sudo_fail(store: Store) -> None:
    detector = LocalLogDetector(store)
    alerts = detector.handle_event(Event(
        ts=now(), source="journal", kind="sudo_failed",
        data={"user": "khoa", "message": "authentication failure"},
    ))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LOCAL_SUDO_FAIL"
    assert alerts[0].subject == "khoa"


def test_local_log_usb_new(store: Store) -> None:
    detector = LocalLogDetector(store)
    alerts = detector.handle_event(Event(
        ts=now(), source="journal", kind="usb_new", data={"message": "New USB device found"},
    ))
    assert alerts[0].rule_id == "LOCAL_NEW_USB"


def test_local_log_promiscuous_ignores_own_interface(store: Store) -> None:
    detector = LocalLogDetector(store, own_interfaces={"wlo1"})
    alerts = detector.handle_event(Event(
        ts=now(), source="journal", kind="promisc_mode",
        data={"interface": "wlo1", "message": "device wlo1 entered promiscuous mode"},
    ))
    assert alerts == []  # chính Shield đang sniff trên wlo1, không tự báo động


def test_local_log_promiscuous_other_interface_alerts(store: Store) -> None:
    detector = LocalLogDetector(store, own_interfaces={"wlo1"})
    alerts = detector.handle_event(Event(
        ts=now(), source="journal", kind="promisc_mode",
        data={"interface": "eth0", "message": "device eth0 entered promiscuous mode"},
    ))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LOCAL_PROMISC_MODE"
