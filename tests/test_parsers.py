"""Test các hàm parse/validate thuần (không I/O, không mạng thật) — nơi dễ
crash nhất khi input thực tế lệch giả định (đúng như bug DHCP option đã gặp).
"""

from __future__ import annotations

import ipaddress

from shield.agent import actions
from packet_helper.sniffers import safe_dhcp_options
from shield.agent.collectors.discovery import _parse_arp_scan, _parse_nmap_sn
from shield.agent.collectors.traffic import _pick_protocol_label
from shield.agent.router_backends import _parse_conntrack


# --- arp_sniffer.safe_dhcp_options — chỗ crash thật đã gặp ---


def test_safe_dhcp_options_normal_tuples():
    raw = [("message-type", 2), ("server_id", "192.168.1.1"), ("lease_time", 86400)]
    assert safe_dhcp_options(raw) == {
        "message-type": 2, "server_id": "192.168.1.1", "lease_time": 86400,
    }


def test_safe_dhcp_options_malformed_entry_ignored():
    """Đây chính là input từng crash: 1 entry có 3 phần tử thay vì 2."""
    raw = [("message-type", 2), ("weird_vendor_option", "a", "b"), "pad", ("end",)]
    result = safe_dhcp_options(raw)
    assert result == {"message-type": 2}  # chỉ giữ tuple đúng 2 phần tử


def test_safe_dhcp_options_empty_list():
    assert safe_dhcp_options([]) == {}


# --- discovery.py: parse output arp-scan / nmap -sn ---


def test_parse_arp_scan_normal_output():
    output = (
        "Interface: wlo1, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.1.10\n"
        "192.168.1.1\t00:11:22:33:44:55\tTP-Link Corporation\n"
        "192.168.1.20\t66:77:88:99:aa:bb\t(Unknown)\n"
        "\n"
        "2 packets received by filter, 0 packets dropped by kernel\n"
    )
    hosts = _parse_arp_scan(output)
    assert len(hosts) == 2
    assert hosts[0] == {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor_hint": "TP-Link Corporation"}
    assert hosts[1]["vendor_hint"] == "(Unknown)"


def test_parse_arp_scan_empty_output():
    assert _parse_arp_scan("") == []


def test_parse_nmap_sn_normal_output():
    output = (
        "Nmap scan report for 192.168.1.1\n"
        "Host is up (0.0010s latency).\n"
        "MAC Address: 00:11:22:33:44:55 (TP-Link)\n"
        "Nmap scan report for router.lan (192.168.1.254)\n"
        "Host is up.\n"
        "MAC Address: AA:BB:CC:DD:EE:FF (Unknown vendor)\n"
    )
    hosts = _parse_nmap_sn(output)
    assert len(hosts) == 2
    assert hosts[0]["ip"] == "192.168.1.1"
    assert hosts[0]["mac"] == "00:11:22:33:44:55"
    assert hosts[1]["ip"] == "192.168.1.254"


def test_parse_nmap_sn_no_mac_lines_produces_no_hosts():
    """Host trả lời ping nhưng không có dòng MAC Address (ví dụ chính máy
    mình, hoặc host ngoài subnet local) -> không gán được MAC, bỏ qua."""
    output = "Nmap scan report for 192.168.1.1\nHost is up.\n"
    assert _parse_nmap_sn(output) == []


# --- actions.py: validate CIDR, phân loại rủi ro cổng, parse nmap -sV ---


def test_validate_authorized_cidr_ok():
    ok, result = actions.validate_authorized_cidr("192.168.1.0/24")
    assert ok
    assert result == "192.168.1.0/24"


def test_validate_authorized_cidr_normalizes_host_bits():
    ok, result = actions.validate_authorized_cidr("192.168.1.5/24")
    assert ok
    assert result == "192.168.1.0/24"


def test_validate_authorized_cidr_rejects_too_large():
    ok, msg = actions.validate_authorized_cidr("10.0.0.0/8")
    assert not ok
    assert "quá lớn" in msg


def test_validate_authorized_cidr_rejects_garbage():
    ok, msg = actions.validate_authorized_cidr("not-a-cidr")
    assert not ok


def test_classify_port_risk():
    assert actions.classify_port_risk(23) == "danger"    # Telnet
    assert actions.classify_port_risk(445) == "danger"   # SMB
    assert actions.classify_port_risk(22) == "caution"    # SSH
    assert actions.classify_port_risk(8080) == "caution"
    assert actions.classify_port_risk(12345) == "safe"


def test_parse_nmap_sV_output():
    output = (
        "PORT     STATE SERVICE  VERSION\n"
        "22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu\n"
        "80/tcp   open  http     nginx 1.18.0\n"
        "445/tcp  open  microsoft-ds\n"
    )
    ports = actions._parse_nmap_sV(output)
    assert len(ports) == 3
    assert ports[0]["port"] == 22
    assert ports[0]["proto"] == "tcp"
    assert ports[0]["service"] == "ssh"
    assert ports[0]["version"] == "OpenSSH 8.9p1 Ubuntu"
    assert ports[0]["risk"] == "caution"
    assert ports[0]["cve_hints"] == []
    assert "SSH" in ports[0]["advice"]
    assert ports[2]["risk"] == "danger"  # 445 = SMB
    assert ports[2]["cve_hints"][0]["cve"] == "CVE-2017-0144"  # EternalBlue


def test_advice_for_port_known_and_unknown():
    assert "SMBv1" in actions.advice_for_port(445)
    assert actions.advice_for_port(12345) == ""


def test_cve_hints_for_port_known_and_unknown():
    hints = actions.cve_hints_for_port(3389)
    assert hints and hints[0]["cve"] == "CVE-2019-0708"  # BlueKeep
    assert actions.cve_hints_for_port(12345) == []


# --- actions.py: lọc kết nối WiFi từ output nmcli -t -f NAME,TYPE ---


def test_filter_wifi_connection_names_basic():
    out = (
        "Home-Net:802-11-wireless\n"
        "Wired connection 1:802-3-ethernet\n"
        "Office-VPN:vpn\n"
        "Guest-5G:wifi\n"
    )
    assert actions._filter_wifi_connection_names(out) == ["Home-Net", "Guest-5G"]


def test_filter_wifi_connection_names_empty():
    assert actions._filter_wifi_connection_names("") == []


def test_filter_wifi_connection_names_malformed_line_ignored():
    out = "no-colon-here\nHome-Net:802-11-wireless\n"
    assert actions._filter_wifi_connection_names(out) == ["Home-Net"]


# --- router_backends.py: parse /proc/net/nf_conntrack ---


def test_parse_conntrack_basic_line():
    lan_net = ipaddress.ip_network("192.168.1.0/24")
    line = (
        "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.50 dst=93.184.216.34 "
        "sport=51820 dport=443 packets=10 bytes=4021 src=93.184.216.34 dst=192.168.1.50 "
        "sport=443 dport=51820 packets=8 bytes=8932 [ASSURED] mark=0 zone=0 use=2\n"
    )
    hosts = _parse_conntrack(line, lan_net)
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "192.168.1.50"
    assert hosts[0]["tx_bytes"] == 4021  # src=192.168.1.50 ở tuple 1
    assert hosts[0]["rx_bytes"] == 8932  # dst=192.168.1.50 ở tuple 2


def test_parse_conntrack_filters_out_wan_ips():
    lan_net = ipaddress.ip_network("192.168.1.0/24")
    line = (
        "ipv4 2 udp 17 29 src=203.0.113.5 dst=8.8.8.8 sport=5000 dport=53 bytes=64 "
        "src=8.8.8.8 dst=203.0.113.5 sport=53 dport=5000 bytes=128 mark=0 use=1\n"
    )
    # Không IP nào thuộc 192.168.1.0/24 -> không có thiết bị LAN nào trong kết quả.
    assert _parse_conntrack(line, lan_net) == []


def test_parse_conntrack_empty_input():
    lan_net = ipaddress.ip_network("192.168.1.0/24")
    assert _parse_conntrack("", lan_net) == []


def test_parse_conntrack_malformed_line_ignored():
    lan_net = ipaddress.ip_network("192.168.1.0/24")
    assert _parse_conntrack("garbage line not matching pattern\n", lan_net) == []


# --- traffic.py: chọn nhãn giao thức từ frame.protocols của tshark ---


def test_pick_protocol_label_prefers_application_layer():
    assert _pick_protocol_label("eth:ethertype:ip:tcp:tls:http2") == "http2"
    assert _pick_protocol_label("eth:ethertype:ip:udp:dns") == "dns"
    assert _pick_protocol_label("eth:ethertype:ip:tcp:tls") == "tls"


def test_pick_protocol_label_falls_back_to_transport():
    assert _pick_protocol_label("eth:ethertype:ip:tcp") == "tcp"
    assert _pick_protocol_label("eth:ethertype:ip:udp") == "udp"


def test_pick_protocol_label_empty_string():
    assert _pick_protocol_label("") == "other"
