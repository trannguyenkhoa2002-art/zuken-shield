"""Test Store — tập trung vào audit_snapshots (diff baseline theo thời gian,
mục 4 trong bản đánh giá) vì đây là logic thuần dễ test, không cần mock I/O
mạng.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.common.models import Alert


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(path=tmp_path / "test.db")
    yield s
    s.close()


PORTS_V1 = [
    {"port": 22, "proto": "tcp", "service": "ssh", "version": "", "risk": "caution"},
    {"port": 80, "proto": "tcp", "service": "http", "version": "", "risk": "safe"},
]


def test_diff_with_fewer_than_two_snapshots_returns_none(store: Store):
    assert store.diff_latest_audit_snapshots("127.0.0.1") is None
    store.save_audit_snapshot("127.0.0.1", PORTS_V1)
    assert store.diff_latest_audit_snapshots("127.0.0.1") is None


def test_diff_detects_added_and_removed_ports(store: Store):
    store.save_audit_snapshot("127.0.0.1", PORTS_V1)
    ports_v2 = [
        {"port": 22, "proto": "tcp", "service": "ssh", "version": "", "risk": "caution"},
        {"port": 445, "proto": "tcp", "service": "smb", "version": "", "risk": "danger"},
    ]
    store.save_audit_snapshot("127.0.0.1", ports_v2)

    diff = store.diff_latest_audit_snapshots("127.0.0.1")
    assert diff is not None
    assert [p["port"] for p in diff["added"]] == [445]
    assert [p["port"] for p in diff["removed"]] == [80]


def test_diff_no_change_gives_empty_added_removed(store: Store):
    store.save_audit_snapshot("127.0.0.1", PORTS_V1)
    store.save_audit_snapshot("127.0.0.1", list(PORTS_V1))

    diff = store.diff_latest_audit_snapshots("127.0.0.1")
    assert diff is not None
    assert diff["added"] == []
    assert diff["removed"] == []


def test_diff_is_scoped_per_host(store: Store):
    store.save_audit_snapshot("127.0.0.1", PORTS_V1)
    store.save_audit_snapshot("192.168.1.50", PORTS_V1)
    # 192.168.1.50 chỉ có 1 snapshot -> chưa đủ để diff dù host khác có 2.
    assert store.diff_latest_audit_snapshots("192.168.1.50") is None


def test_list_audit_snapshots_orders_newest_first(store: Store):
    store.save_audit_snapshot("127.0.0.1", PORTS_V1)
    store.save_audit_snapshot("127.0.0.1", [])
    snaps = store.list_audit_snapshots("127.0.0.1")
    assert len(snaps) == 2
    assert snaps[0]["ts"] >= snaps[1]["ts"]


def test_alert_security_metadata_roundtrip(store: Store):
    alert = Alert(
        ts=1.0, rule_id="TEST_RISK", severity="warning", title="test",
        detail="detail", subject="host", risk_score=67, evidence_strength=0.83,
        policy_action="alert",
    )
    store.insert_alert(alert)
    saved = store.recent_alerts(limit=1)[0]
    assert saved["risk_score"] == 67
    assert saved["confidence"] == pytest.approx(0.83)
    assert saved["policy_action"] == "alert"


def test_fim_baseline_replace_is_atomic_and_removes_stale_paths(store: Store):
    store.replace_fim_baseline({"/a": {"sha256": "one"}, "/b": {"sha256": "two"}})
    assert set(store.load_fim_baseline()) == {"/a", "/b"}
    store.replace_fim_baseline({"/b": {"sha256": "changed"}})
    assert store.load_fim_baseline() == {"/b": {"sha256": "changed"}}


def test_store_survives_concurrent_writers_from_many_threads(tmp_path: Path):
    """Store dùng chung 1 sqlite3.Connection với check_same_thread=False, và bị
    gọi từ nhiều luồng: event loop agent, các asyncio.to_thread (snapshot
    endpoint, backup DB, stop_process) và luồng callback của scapy AsyncSniffer.
    Không đồng bộ thì agent chết lúc khởi động với
    `OperationalError: cannot commit - no transaction is active` hoặc
    `InterfaceError: bad parameter or other API misuse` (đã gặp trên máy thật:
    shield-agent crash-loop 6 lần rồi failed).
    """
    import threading

    s = Store(path=tmp_path / "concurrent.db")
    errors: list[str] = []

    def writer(index: int) -> None:
        try:
            for i in range(200):
                s.set_collector_health(f"c{index}", "test", True, "running", state="running")
                s.add_audit_log("probe", {"i": i}, "ok")
        except Exception as exc:                     # noqa: BLE001 - ghi lại mọi lỗi để assert
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(s.collector_health()) == 6
    s.close()
