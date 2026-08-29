"""Làm mới phiên quét: quên MÔ TẢ thiết bị, không xoá lịch sử."""

from __future__ import annotations

import time

import pytest

from shield.agent.store import Store
from shield.common.models import Alert, Event


@pytest.fixture
def store(tmp_path):
    store = Store(tmp_path / "shield.db")
    now = time.time()
    store.insert_event(Event(now, "arp", "seen", {"mac": "aa:bb:cc:dd:ee:01"}))
    store.insert_alert(Alert(now, "DEVICE_NEW", "warning", "new", "d", "aa:bb:cc:dd:ee:02"))
    store.upsert_device("aa:bb:cc:dd:ee:01", "10.0.0.1", "Fresh")
    store.upsert_device("aa:bb:cc:dd:ee:02", "10.0.0.2", "Stale")
    store.conn.execute("UPDATE devices SET last_seen=? WHERE mac=?",
                       (now - 30 * 86400, "aa:bb:cc:dd:ee:02"))
    store.conn.commit()
    yield store
    store.close()


def test_only_old_devices_are_forgotten(store):
    result = store.reset_scan_session(older_than_days=7)
    assert result["devices_removed"] == 1
    assert [device["mac"] for device in store.list_devices()] == ["aa:bb:cc:dd:ee:01"]


def test_everything_can_be_forgotten(store):
    assert store.reset_scan_session()["devices_removed"] == 2
    assert store.list_devices() == []
    assert store.list_device_identities() == []


def test_evidence_is_never_touched(store):
    """Quên một thiết bị là quên MÔ TẢ nó, không phải xoá những gì nó đã làm."""
    events_before = store.conn.execute("SELECT count(*) FROM events").fetchone()[0]
    alerts_before = store.conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    ledger_before = store.conn.execute("SELECT count(*) FROM forensic_ledger").fetchone()[0]
    store.reset_scan_session()
    assert store.conn.execute("SELECT count(*) FROM events").fetchone()[0] == events_before
    assert store.conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == alerts_before
    assert store.conn.execute(
        "SELECT count(*) FROM forensic_ledger").fetchone()[0] >= ledger_before


def test_the_reset_is_written_to_the_audit_log(store):
    """Một thao tác xoá không để lại dấu vết là thứ kẻ tấn công sẽ dùng."""
    store.reset_scan_session(older_than_days=7)
    row = store.conn.execute(
        "SELECT action_id, params FROM audit_log ORDER BY ts DESC LIMIT 1").fetchone()
    assert row[0] == "reset_scan_session"
    assert "aa:bb:cc:dd:ee:02" in row[1], "không ghi lại đã quên thiết bị nào"


def test_resetting_an_empty_list_is_harmless(tmp_path):
    store = Store(tmp_path / "empty.db")
    assert store.reset_scan_session()["devices_removed"] == 0
    store.close()


def test_an_identity_with_other_macs_survives(store):
    """Danh tính gộp nhiều MAC mà mới quên một cái thì phải giữ lại."""
    identities = store.list_device_identities()
    assert identities
    device_id = identities[0]["device_id"]
    store.conn.execute(
        "INSERT INTO device_links(mac,device_id,confidence,reason,user_confirmed) "
        "VALUES('99:99:99:99:99:99',?,1.0,'test',0)", (device_id,))
    store.conn.commit()
    macs = {item["mac"] for item in store.list_devices()}
    store.reset_scan_session(older_than_days=None)
    remaining = {row[0] for row in store.conn.execute("SELECT device_id FROM device_identities")}
    assert device_id in remaining, "xoá mất danh tính vẫn còn MAC khác"
    assert "99:99:99:99:99:99" not in macs
