"""Syslog receiver + ranh giới tin cậy (kế hoạch 1.1 mục A2).

Không mở cổng thật: `handle_payload` nhận thẳng bytes + địa chỉ nguồn, nên
mọi tình huống — kể cả IP giả mạo và flood — dựng được trong bộ nhớ.
"""

from __future__ import annotations

import asyncio

import pytest

from shield.agent.bus import Bus
from shield.agent.collectors.syslog_server import (
    MAX_DATAGRAM_BYTES,
    RateLimiter,
    SyslogCollector,
    allowed_sources,
    parse_priority,
    parse_syslog,
    source_is_allowed,
)
from shield.common.models import Alert, Event
from shield.security.anomaly import LocalBaselineDetector
from shield.security.trust import (
    AUTHENTICATED,
    UNAUTHENTICATED,
    event_trust,
    may_enter_forensic_ledger,
    may_train_baseline,
    stamp_alert,
)

RFC3164 = b"<34>Oct 11 22:14:15 router su[1234]: 'su root' failed for admin"
RFC5424 = b"<165>1 2003-10-11T22:14:15.003Z router evntslog - ID47 - login failed"


# --- parser ---


def test_rfc3164_is_parsed_into_fields():
    parsed = parse_syslog(RFC3164.decode())
    assert parsed["format"] == "rfc3164"
    assert parsed["facility"] == "auth" and parsed["severity"] == "crit"
    assert parsed["reported_hostname"] == "router"
    assert parsed["app"] == "su" and parsed["procid"] == "1234"
    assert parsed["message"] == "'su root' failed for admin"


def test_rfc5424_is_parsed_into_fields():
    parsed = parse_syslog(RFC5424.decode())
    assert parsed["format"] == "rfc5424"
    assert parsed["app"] == "evntslog" and parsed["msgid"] == "ID47"
    assert "login failed" in parsed["message"]


def test_priority_decoding_matches_the_rfc():
    assert parse_priority("34") == ("auth", "crit")
    assert parse_priority("0") == ("kern", "emerg")
    assert parse_priority("999") == ("unknown", "unknown")
    assert parse_priority("không phải số") == ("unknown", "unknown")


@pytest.mark.parametrize("payload", [
    "", "   ", "không có priority", "<>", "<999999999>x", "<34>", "<34>thiếu hết",
    "<34>Oct 11 22:14:15", "\x00\x00\x00", "<-1>Oct 11 22:14:15 host msg",
])
def test_malformed_input_is_dropped_not_guessed(payload):
    """Đoán bừa nghĩa là để người gửi tự chọn nội dung mọi trường."""
    assert parse_syslog(payload) is None


def test_parser_survives_hostile_input_without_hanging():
    """Chống ReDoS: chuỗi rất dài không được làm regex chạy mãi."""
    parse_syslog("<34>" + "A" * 100_000)
    parse_syslog("<34>Oct 11 22:14:15 " + "h" * 50_000 + " msg")


def test_long_fields_are_truncated():
    parsed = parse_syslog("<34>Oct 11 22:14:15 host app: " + "x" * 10_000)
    assert len(parsed["message"]) <= 2000
    assert len(parsed["reported_hostname"]) <= 255


# --- allowlist ---


def test_an_empty_allowlist_accepts_nothing():
    """Fail closed. Không có chế độ "nhận tất cả"."""
    assert allowed_sources("") == ()
    assert source_is_allowed("192.168.1.1", allowed_sources("")) is False


def test_allowlist_accepts_ips_and_cidrs():
    networks = allowed_sources("192.168.1.1, 10.0.0.0/8")
    assert source_is_allowed("192.168.1.1", networks)
    assert source_is_allowed("10.4.5.6", networks)
    assert not source_is_allowed("192.168.1.2", networks)
    assert not source_is_allowed("8.8.8.8", networks)


def test_invalid_allowlist_entries_are_skipped_not_treated_as_wildcards():
    networks = allowed_sources("không-phải-ip, *, 10.0.0.0/8")
    assert not source_is_allowed("1.2.3.4", networks)
    assert source_is_allowed("10.1.1.1", networks)


# --- rate limit ---


def test_rate_limiter_stops_a_flood_from_one_source():
    limiter = RateLimiter(rate_per_s=10)
    allowed = sum(limiter.allow("10.0.0.1", at=100.0) for _ in range(100))
    assert allowed == 10


def test_rate_limiter_refills_over_time():
    limiter = RateLimiter(rate_per_s=10)
    for _ in range(10):
        limiter.allow("10.0.0.1", at=100.0)
    assert limiter.allow("10.0.0.1", at=100.0) is False
    assert limiter.allow("10.0.0.1", at=101.0) is True


def test_rate_limiter_cannot_be_made_to_eat_memory_by_spoofed_sources():
    """Giả mạo IP nguồn ngẫu nhiên không được biến chính bộ đếm thành chỗ
    tiêu thụ bộ nhớ."""
    limiter = RateLimiter(rate_per_s=10, max_sources=50)
    for i in range(500):
        limiter.allow(f"10.0.{i // 256}.{i % 256}", at=100.0)
    assert len(limiter._buckets) <= 51


# --- collector ---


def _collector(**kwargs) -> tuple[SyslogCollector, Bus]:
    bus = Bus(max_queue_size=64)
    queue = bus.subscribe()
    collector = SyslogCollector(bus, allowlist="192.168.1.0/24", **kwargs)
    return collector, queue


def test_an_allowed_source_produces_an_unauthenticated_event():
    collector, queue = _collector()
    assert asyncio.run(collector.handle_payload(RFC3164, "192.168.1.1")) is True
    event = queue.get_nowait()
    assert event.source == "syslog"
    assert event.data["trust"] == UNAUTHENTICATED
    assert event.data["origin"] == "syslog:192.168.1.1"
    assert event.data["source_ip"] == "192.168.1.1"


def test_a_source_outside_the_allowlist_is_dropped():
    collector, queue = _collector()
    assert asyncio.run(collector.handle_payload(RFC3164, "10.9.9.9")) is False
    assert queue.empty()
    assert collector.rejected_source == 1


def test_oversized_datagrams_are_dropped_before_parsing():
    collector, queue = _collector()
    huge = b"<34>Oct 11 22:14:15 host app: " + b"x" * (MAX_DATAGRAM_BYTES + 1)
    assert asyncio.run(collector.handle_payload(huge, "192.168.1.1")) is False
    assert queue.empty()
    assert collector.rejected_size == 1


def test_the_claimed_hostname_never_becomes_the_identity():
    """Hostname trong gói syslog là do NGƯỜI GỬI tự khai. Dùng nó làm danh
    tính nghĩa là cho phép bất kỳ ai mạo danh bất kỳ thiết bị nào."""
    collector, queue = _collector()
    spoofed = b"<34>Oct 11 22:14:15 gateway-that-i-am-not su: hi"
    asyncio.run(collector.handle_payload(spoofed, "192.168.1.77"))
    event = queue.get_nowait()
    assert event.data["source_ip"] == "192.168.1.77"
    assert event.data["origin"] == "syslog:192.168.1.77"
    assert event.data["reported_hostname"] == "gateway-that-i-am-not"


def test_the_server_refuses_to_start_without_an_allowlist():
    bus = Bus()
    collector = SyslogCollector(bus, allowlist="")
    assert asyncio.run(collector.start()) is False
    assert collector.stats()["listening"] is False


def test_default_bind_is_loopback_so_opening_to_the_lan_is_deliberate():
    collector = SyslogCollector(Bus(), allowlist="10.0.0.0/8")
    assert collector.host == "127.0.0.1"


# --- ranh giới tin cậy ---


def _syslog_event() -> Event:
    return Event(ts=1.0, source="syslog", kind="syslog_message",
                 data={"trust": UNAUTHENTICATED, "origin": "syslog:192.168.1.1"})


def test_unauthenticated_alerts_never_reach_the_forensic_ledger():
    """Nếu lọt vào, kẻ tấn công bơm được bằng chứng giả và toàn bộ chuỗi hash
    mất giá trị — kể cả những dòng thật."""
    alert = Alert(1.0, "R", "warning", "t", "d", "s")
    assert may_enter_forensic_ledger(stamp_alert(alert, _syslog_event())) is False
    local = Event(ts=1.0, source="journal", kind="x", data={})
    assert may_enter_forensic_ledger(stamp_alert(alert, local)) is True


def test_unauthenticated_alerts_are_capped_below_critical():
    """Bơm được alert critical giả là bơm được thói quen bỏ qua cảnh báo."""
    alert = Alert(1.0, "R", "critical", "t", "d", "s")
    stamped = stamp_alert(alert, _syslog_event())
    assert stamped.severity == "warning"
    assert stamped.evidence["severity_capped_from"] == "critical"


def test_authenticated_alerts_keep_their_severity():
    alert = Alert(1.0, "R", "critical", "t", "d", "s")
    stamped = stamp_alert(alert, Event(ts=1.0, source="journal", kind="x", data={}))
    assert stamped.severity == "critical"
    assert stamped.evidence["trust"] == AUTHENTICATED


def test_unauthenticated_events_never_train_the_baseline():
    """Đầu độc baseline khiến hành vi tấn công thật thành "đã thấy rồi"."""
    assert may_train_baseline(_syslog_event()) is False
    assert may_train_baseline(Event(ts=1.0, source="endpoint", kind="x", data={})) is True
    assert may_train_baseline(Event(ts=1.0, source="a", kind="x", data={"synthetic": True})) is False


def test_the_baseline_detector_actually_refuses_unauthenticated_input():
    class NeverAsked:
        def observe_behavior(self, *_args):  # pragma: no cover - phải không được gọi
            raise AssertionError("baseline không được học từ nguồn không xác thực")

    detector = LocalBaselineDetector(NeverAsked())
    event = Event(ts=1.0, source="syslog", kind="process_exec",
                  data={"exe": "/usr/bin/curl", "trust": UNAUTHENTICATED})
    assert detector.handle_event(event) == []


def test_event_trust_defaults_to_authenticated_for_local_collectors():
    assert event_trust(Event(ts=1.0, source="journal", kind="x", data={})) == AUTHENTICATED


def test_kernel_drops_are_visible(monkeypatch, tmp_path):
    """Mất gói ở bộ đệm nhân phải hiện ra, không được im lặng.

    Bộ đếm nội bộ chỉ đếm gói đọc được; khi nguồn bắn nhanh hơn vòng lặp đọc,
    nhân vứt gói trước khi collector thấy và mọi con số vẫn đẹp.
    """
    from shield.agent.bus import Bus
    from shield.agent.collectors.syslog_server import SyslogCollector

    collector = SyslogCollector(Bus(), port=5514)
    proc = tmp_path / "udp"
    proc.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode ref pointer drops\n"
        " 3389: 0100007F:158A 00000000:0000 07 00000000:00000000 00:00000000 "
        "00000000  1000        0 12345 2 0000000000000000 4211\n",
        encoding="ascii",
    )
    real_open = open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/proc/net/udp":
            return real_open(proc, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    assert collector.kernel_dropped() == 4211
    assert collector.stats()["kernel_dropped"] == 4211


def test_unknown_drop_count_is_not_reported_as_zero(monkeypatch):
    """"Không đọc được" khác "không mất gói" — trả 0 ở đây là nói dối."""
    from shield.agent.bus import Bus
    from shield.agent.collectors.syslog_server import SyslogCollector

    collector = SyslogCollector(Bus(), port=5514)

    def boom(*args, **kwargs):
        raise OSError("no /proc")

    monkeypatch.setattr("builtins.open", boom)
    assert collector.kernel_dropped() == -1
