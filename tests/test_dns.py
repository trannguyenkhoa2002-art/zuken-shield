"""Test phần tự kiểm soát DNS — parser thuần (dns_audit) + DnsDetector.

Không gọi resolvectl/dig/nmcli thật: mọi hàm đọc hệ thống đã được tách sao
cho phần logic là hàm thuần nhận chuỗi, test được trực tiếp.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shield.agent import dns_audit as d
from shield.agent.detectors.dns import BASELINE_DNS_SERVERS, DnsDetector
from shield.agent.store import Store
from shield.common.models import Event, now


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(path=tmp_path / "test.db")
    yield s
    s.close()


# --- parse_resolvectl ---

RESOLVECTL_OUT = """Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
resolv.conf mode: stub

Link 2 (wlo1)
    Current Scopes: DNS
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1 1.1.1.1
        DNS Domain: lan
"""


def test_parse_resolvectl_dedupes_and_keeps_order():
    assert d.parse_resolvectl(RESOLVECTL_OUT) == ["192.168.1.1", "1.1.1.1"]


def test_parse_resolvectl_empty():
    assert d.parse_resolvectl("") == []


def test_parse_resolvectl_ignores_non_ip_tokens():
    out = "DNS Servers: not-an-ip 8.8.8.8\n"
    assert d.parse_resolvectl(out) == ["8.8.8.8"]


# --- parse_resolv_conf ---


def test_parse_resolv_conf_skips_comments_and_options():
    content = (
        "# Managed by systemd-resolved\n"
        "nameserver 127.0.0.53\n"
        "options edns0\n"
        "nameserver 8.8.8.8\n"
        "; another comment\n"
        "nameserver notanip\n"
    )
    assert d.parse_resolv_conf(content) == ["127.0.0.53", "8.8.8.8"]


def test_parse_resolv_conf_empty():
    assert d.parse_resolv_conf("") == []


# --- parse_hosts_overrides ---

HOSTS = """127.0.0.1 localhost
127.0.1.1 my-laptop
::1 ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
203.0.113.9 www.mybank.example
# 198.51.100.1 commented.example
"""


def test_parse_hosts_overrides_finds_suspicious_entry():
    entries = d.parse_hosts_overrides(HOSTS, hostname="my-laptop")
    assert len(entries) == 1
    assert entries[0]["ip"] == "203.0.113.9"
    assert entries[0]["names"] == ["www.mybank.example"]


def test_parse_hosts_overrides_filters_own_hostname():
    """127.0.1.1 <tên-máy> là dòng chuẩn của Ubuntu — không được coi là bất
    thường, nếu không tab DNS lúc nào cũng có 1 cảnh báo giả."""
    names = [n for e in d.parse_hosts_overrides(HOSTS, hostname="my-laptop") for n in e["names"]]
    assert "my-laptop" not in names


def test_parse_hosts_overrides_keeps_loopback_blocking_entry():
    """Trỏ domain về 127.0.0.1 để chặn là kỹ thuật của cả adblock lẫn mã độc
    (chặn cập nhật antivirus) — vẫn phải hiện ra cho người dùng xem."""
    entries = d.parse_hosts_overrides("127.0.0.1 updates.antivirus.example\n")
    assert entries[0]["names"] == ["updates.antivirus.example"]


def test_parse_hosts_overrides_ignores_malformed_lines():
    assert d.parse_hosts_overrides("just-one-token\nnot-an-ip somename\n\n") == []


# --- parse_dig_answers / compare_answers ---


def test_parse_dig_answers_keeps_only_ips():
    out = "example.com.\n93.184.216.34\n2606:2800:220::1\ngarbage\n"
    assert d.parse_dig_answers(out) == ["93.184.216.34", "2606:2800:220::1"]


def test_compare_answers_overlap_is_ok():
    assert d.compare_answers(["1.2.3.4"], ["1.2.3.4", "5.6.7.8"]) == "ok"


def test_compare_answers_disjoint_is_suspect():
    assert d.compare_answers(["10.0.0.1"], ["93.184.216.34"]) == "suspect"


def test_compare_answers_missing_side_is_unknown():
    assert d.compare_answers([], ["1.1.1.1"]) == "unknown"
    assert d.compare_answers(["1.1.1.1"], []) == "unknown"


# --- DnsDetector ---


def _resolvers_event(servers: list[str]) -> Event:
    return Event(ts=now(), source="dns_monitor", kind="dns_resolvers", data={"servers": servers})


def test_first_resolvers_seen_learns_baseline_without_alert(store: Store):
    det = DnsDetector(store)
    assert det.handle_event(_resolvers_event(["192.168.1.1"])) == []
    assert store.get_baseline(BASELINE_DNS_SERVERS) == "192.168.1.1"


def test_unchanged_resolvers_no_alert(store: Store):
    det = DnsDetector(store)
    det.handle_event(_resolvers_event(["192.168.1.1", "1.1.1.1"]))
    # Thứ tự đảo nhưng cùng tập -> không phải thay đổi thật.
    assert det.handle_event(_resolvers_event(["1.1.1.1", "192.168.1.1"])) == []


def test_changed_resolvers_alerts_critical(store: Store):
    det = DnsDetector(store)
    det.handle_event(_resolvers_event(["192.168.1.1"]))
    alerts = det.handle_event(_resolvers_event(["203.0.113.9"]))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "DNS_RESOLVER_CHANGED"
    assert alerts[0].severity == "critical"
    assert alerts[0].evidence["baseline"] == "192.168.1.1"


def test_changed_resolvers_updates_baseline_so_it_alerts_once(store: Store):
    det = DnsDetector(store)
    det.handle_event(_resolvers_event(["192.168.1.1"]))
    det.handle_event(_resolvers_event(["203.0.113.9"]))
    assert det.handle_event(_resolvers_event(["203.0.113.9"])) == []


def test_empty_resolvers_ignored(store: Store):
    """Đọc hụt (mạng chưa lên) không được xoá/đổi baseline."""
    det = DnsDetector(store)
    det.handle_event(_resolvers_event(["192.168.1.1"]))
    assert det.handle_event(_resolvers_event([])) == []
    assert store.get_baseline(BASELINE_DNS_SERVERS) == "192.168.1.1"


def _query_event(server_ip: str) -> Event:
    return Event(
        ts=now(),
        source="dns_watch",
        kind="dns_query_out",
        data={"server_ip": server_ip, "known": ["192.168.1.1"]},
    )


def test_unexpected_dns_server_alerts_warning(store: Store):
    det = DnsDetector(store)
    alerts = det.handle_event(_query_event("8.8.4.4"))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "DNS_UNEXPECTED_SERVER"
    assert alerts[0].severity == "warning"


def test_unexpected_dns_server_deduped(store: Store):
    """1 app bắn hàng nghìn truy vấn không được tạo hàng nghìn alert."""
    det = DnsDetector(store)
    det.handle_event(_query_event("8.8.4.4"))
    assert det.handle_event(_query_event("8.8.4.4")) == []


def test_unexpected_dns_server_different_ips_both_alert(store: Store):
    det = DnsDetector(store)
    det.handle_event(_query_event("8.8.4.4"))
    alerts = det.handle_event(_query_event("9.9.9.9"))
    assert len(alerts) == 1
    assert alerts[0].subject == "9.9.9.9"
