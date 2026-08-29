from pathlib import Path

from shield.agent.store import Store
from shield.common.models import Alert
from shield.security.device_intelligence import infer_device_profile


def test_profiler_is_explainable_and_not_overconfident():
    unknown = infer_device_profile({})
    assert unknown.device_type == "Unknown"
    assert unknown.confidence == 0.2
    assert not unknown.evidence

    printer = infer_device_profile({"vendor": "Brother Industries", "open_ports": [631, 9100]})
    assert printer.device_type == "Printer"
    assert 0.5 < printer.confidence <= 0.95
    assert {item.signal for item in printer.evidence} == {"mac_vendor", "open_ports"}


def test_old_scanned_devices_are_backfilled_with_profiles(tmp_path: Path):
    path = tmp_path / "old.db"
    store = Store(path)
    store.conn.execute(
        "INSERT INTO devices(mac,ip,vendor,hostname,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
        ("00:11:22:33:44:55", "192.0.2.10", "Brother", "printer-office", 1, 2),
    )
    store.conn.execute("DELETE FROM device_links")
    store.conn.execute("DELETE FROM device_profiles")
    store.conn.execute("DELETE FROM device_identities")
    store.conn.commit(); store.close()

    # Backfill chỉ chạy trong nhánh migration; từ 2.0 nhánh đó phải xin phép.
    reopened = Store(path, allow_migration=True)
    profiles = reopened.list_device_identities()
    assert len(profiles) == 1
    assert profiles[0]["current_ip"] == "192.0.2.10"
    assert profiles[0]["device_type"] == "Printer"
    assert profiles[0]["profile_evidence"]
    reopened.close()


def test_identity_never_auto_merges_mac_and_user_can_merge_split(tmp_path: Path):
    store = Store(tmp_path / "identity.db")
    first = store.observe_device_identity("00:11:22:33:44:55", "192.0.2.1", "QNAP", "nas", {})
    second = store.observe_device_identity("00:11:22:33:44:66", "192.0.2.2", "QNAP", "nas", {})
    assert first != second

    store.merge_device_identities(first, second)
    merged = next(item for item in store.list_device_identities() if item["device_id"] == first)
    assert set(merged["macs"]) == {"00:11:22:33:44:55", "00:11:22:33:44:66"}

    new_id = store.split_device_identity(first, "00:11:22:33:44:66")
    assert new_id != first
    assert len(store.list_device_identities()) == 2
    store.close()


def test_asset_criticality_prioritizes_but_does_not_create_evidence(tmp_path: Path):
    store = Store(tmp_path / "risk.db")
    device_id = store.observe_device_identity("00:11:22:33:44:55", "192.0.2.10", "", "", {})
    store.insert_alert(Alert(
        ts=1, rule_id="TEST", severity="warning", title="test", detail="test",
        subject="192.0.2.10", risk_score=60,
    ))
    store.update_device_metadata(device_id, display_name="Core router", criticality="Critical")
    assert store.list_device_identities()[0]["risk_score"] == 75
    store.close()
