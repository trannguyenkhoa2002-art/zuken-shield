"""Baseline học 3 chiều: hành vi máy, thiết bị, giờ đăng nhập (mục B7)."""

from __future__ import annotations

import time

from shield.agent.store import Store
from shield.common.models import Event
from shield.security.anomaly import (
    LocalBaselineDetector,
    behavior_key,
    device_key,
    login_key,
)


class _Store:
    """Store giả: đã học xong giai đoạn learning, đếm số lần thấy từng khoá."""

    def __init__(self, learning: bool = False) -> None:
        self.counts: dict[str, int] = {}
        self.learning = learning

    def observe_behavior(self, key, _kind, _days):
        previous = self.counts.get(key, 0)
        self.counts[key] = previous + 1
        return previous, self.learning


def _at(hour: int) -> float:
    return time.mktime(time.struct_time((2026, 8, 21, hour, 0, 0, 4, 233, -1)))


def test_a_device_seen_at_a_new_hour_band_is_reported():
    """Một máy lạ lúc 3 giờ sáng khác hẳn cùng máy đó lúc 2 giờ chiều."""
    detector = LocalBaselineDetector(_Store())
    daytime = Event(ts=_at(14), source="discovery", kind="host_seen",
                    data={"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.5"})
    for _ in range(5):
        detector.handle_event(daytime)

    night = Event(ts=_at(3), source="discovery", kind="host_seen",
                  data={"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.5"})
    alerts = detector.handle_event(night)
    assert [a.rule_id for a in alerts] == ["ANOMALY_DEVICE_AT_UNUSUAL_TIME"]
    assert alerts[0].evidence["local_hour"] == 3


def test_a_familiar_device_at_its_usual_hour_stays_quiet():
    detector = LocalBaselineDetector(_Store())
    event = Event(ts=_at(14), source="discovery", kind="host_seen", data={"mac": "aa:bb:cc:dd:ee:ff"})
    for _ in range(4):
        detector.handle_event(event)
    assert detector.handle_event(event) == []


def test_devices_are_tracked_by_mac_not_by_ip():
    """DHCP đổi IP liên tục. Baseline theo IP sẽ báo động mỗi lần router cấp
    lại địa chỉ — đúng kiểu cảnh báo dạy người dùng bỏ qua cảnh báo."""
    same_mac_new_ip = Event(ts=_at(14), source="discovery", kind="host_seen",
                            data={"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.99"})
    original = Event(ts=_at(14), source="discovery", kind="host_seen",
                     data={"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.5"})
    assert device_key(same_mac_new_ip) == device_key(original)


def test_a_login_outside_the_usual_hours_is_reported():
    detector = LocalBaselineDetector(_Store())
    for hour in (9, 10, 11, 14, 15):
        detector.handle_event(Event(ts=_at(hour), source="probe.journal", kind="ssh_auth_success",
                                    data={"user": "khoa", "probe_host": "may-ban"}))
    alerts = detector.handle_event(Event(ts=_at(3), source="probe.journal", kind="ssh_auth_success",
                                         data={"user": "khoa", "probe_host": "may-ban"}))
    assert [a.rule_id for a in alerts] == ["ANOMALY_LOGIN_AT_UNUSUAL_TIME"]


def test_login_bands_are_finer_than_behaviour_bands():
    """Dải 6 tiếng gộp 18h với 23h làm một — mất đúng ranh giới giữa "tan làm"
    và "nửa đêm"."""
    evening = Event(ts=_at(18), source="s", kind="ssh_auth_success", data={"user": "khoa"})
    midnight = Event(ts=_at(23), source="s", kind="ssh_auth_success", data={"user": "khoa"})
    assert login_key(evening) != login_key(midnight)


def test_different_users_have_separate_login_baselines():
    a = Event(ts=_at(3), source="s", kind="ssh_auth_success", data={"user": "khoa"})
    b = Event(ts=_at(3), source="s", kind="ssh_auth_success", data={"user": "root"})
    assert login_key(a) != login_key(b)


def test_nothing_is_reported_while_still_learning():
    """Trong giai đoạn học, mọi thứ đều là "lần đầu" — báo động lúc này là
    dạy người dùng tắt cảnh báo ngay tuần đầu tiên."""
    detector = LocalBaselineDetector(_Store(learning=True))
    for kind, data in (("host_seen", {"mac": "aa:bb:cc:dd:ee:ff"}),
                       ("ssh_auth_success", {"user": "khoa"}),
                       ("process_exec", {"exe": "/usr/bin/curl"})):
        assert detector.handle_event(Event(ts=_at(3), source="s", kind=kind, data=data)) == []


def test_the_three_dimensions_never_collide():
    """Khoá của ba chiều phải khác nhau, nếu không một lần đăng nhập sẽ dạy
    baseline thiết bị và ngược lại."""
    ts = _at(10)
    keys = {
        behavior_key(Event(ts=ts, source="s", kind="process_exec", data={"exe": "/x"})),
        device_key(Event(ts=ts, source="s", kind="host_seen", data={"mac": "x"})),
        login_key(Event(ts=ts, source="s", kind="ssh_auth_success", data={"user": "x"})),
    }
    assert len(keys) == 3


def test_unrelated_events_are_ignored():
    detector = LocalBaselineDetector(_Store())
    assert detector.handle_event(Event(ts=_at(3), source="s", kind="arp_reply", data={})) == []


def test_the_real_store_records_all_three_dimensions(tmp_path):
    store = Store(tmp_path / "shield.db")
    try:
        # Bỏ giai đoạn learning để kiểm phần đếm.
        store.set_baseline("anomaly_learning_started", str(time.time() - 60 * 86400))
        detector = LocalBaselineDetector(store)
        for kind, data in (("host_seen", {"mac": "aa:bb:cc:dd:ee:ff"}),
                           ("ssh_auth_success", {"user": "khoa"}),
                           ("process_exec", {"exe": "/usr/bin/curl"})):
            alerts = detector.handle_event(Event(ts=_at(3), source="s", kind=kind, data=data))
            assert len(alerts) == 1, f"{kind} không sinh alert lần đầu"
        summary = store.behavior_baseline_summary()
        assert summary
    finally:
        store.close()
