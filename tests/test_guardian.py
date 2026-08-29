"""Guardian — canh chừng Shield từ bên ngoài tiến trình agent (mục B2).

Không gọi systemctl thật, không chạm mạng: mọi kiểm tra nhận `unit` dạng dict
nên test dựng được đủ mọi tình huống, kể cả những cái không tái tạo được trên
máy dev (agent bị kill, ledger bị cắt ngắn).
"""

from __future__ import annotations

import json
import time

from shield.agent.store import Store
from shield.guardian.__main__ import (
    check_agent_is_running,
    check_database,
    check_installation_integrity,
    check_ledger_growth,
    check_restart_storm,
    authorized_shutdown,
    read_state,
    record_findings,
    write_state,
)


def _ids(findings) -> list[str]:
    return [f["rule_id"] for f in findings]


# --- agent còn chạy không ---


def test_a_running_agent_produces_no_findings():
    assert check_agent_is_running({"available": True, "ActiveState": "active"}, None) == []


def test_an_agent_killed_by_someone_else_is_a_critical_finding():
    """Đây là lỗ hổng mà Guardian sinh ra để bịt: `systemctl stop shield-agent`
    trước đây không ai phát hiện, vì thứ phát hiện được lại chết cùng lúc."""
    findings = check_agent_is_running(
        {"available": True, "ActiveState": "inactive", "SubState": "dead"}, None
    )
    assert _ids(findings) == ["GUARDIAN_AGENT_STOPPED"]
    assert findings[0]["severity"] == "critical"


def test_an_operator_shutdown_is_recorded_but_never_alarms():
    """Người dùng bấm "Tắt Shield" trong app không phải là sự cố bảo mật.
    Báo động ở đây sẽ dạy người dùng bỏ qua cảnh báo của Guardian."""
    findings = check_agent_is_running(
        {"available": True, "ActiveState": "inactive", "SubState": "dead"},
        {"ts": time.time(), "reason": "mạng trường học", "principal": "uid=1000"},
    )
    assert _ids(findings) == ["GUARDIAN_AGENT_STOPPED_BY_OPERATOR"]
    assert findings[0]["severity"] == "info"


def test_no_systemd_means_no_findings():
    """Trên máy dev / trong container không có systemd — không được báo động giả."""
    assert check_agent_is_running({"available": False}, None) == []


# --- crash loop bị `Restart=` che mất ---


def test_a_restart_storm_is_reported():
    findings = check_restart_storm({"NRestarts": "14"}, {"restarts": "2"})
    assert _ids(findings) == ["GUARDIAN_AGENT_RESTART_STORM"]
    assert findings[0]["evidence"]["delta"] == 12


def test_a_couple_of_restarts_is_not_a_storm():
    assert check_restart_storm({"NRestarts": "3"}, {"restarts": "2"}) == []


# --- toàn vẹn file cài đặt ---


def test_the_first_run_only_takes_a_baseline(tmp_path):
    """Lần chạy đầu mà báo động thì mọi lần cài mới đều mở màn bằng alert giả."""
    (tmp_path / "code.py").write_text("print('xin chào')")
    findings, snapshot = check_installation_integrity(tmp_path, {}, b"")
    assert findings == []
    assert snapshot


def test_changing_a_file_between_runs_is_critical(tmp_path):
    source = tmp_path / "code.py"
    source.write_text("print('xin chào')")
    _findings, snapshot = check_installation_integrity(tmp_path, {}, b"")
    source.write_text("print('đã bị thay')")
    findings, _snapshot = check_installation_integrity(tmp_path, {"snapshot": snapshot}, b"")
    assert _ids(findings) == ["GUARDIAN_INSTALLATION_CHANGED"]
    assert findings[0]["severity"] == "critical"


def test_an_untouched_installation_stays_quiet(tmp_path):
    (tmp_path / "code.py").write_text("print('xin chào')")
    _findings, snapshot = check_installation_integrity(tmp_path, {}, b"")
    findings, _ = check_installation_integrity(tmp_path, {"snapshot": snapshot}, b"")
    assert findings == []


# --- database và ledger ---


def test_a_deleted_database_is_critical(tmp_path):
    findings, state = check_database(tmp_path / "không-tồn-tại.db")
    assert _ids(findings) == ["GUARDIAN_DATABASE_MISSING"]
    assert state == {}


def test_a_healthy_database_reports_its_ledger_size(tmp_path):
    store = Store(tmp_path / "shield.db")
    store.add_forensic_record("test", {"value": 1})
    store.close()
    findings, state = check_database(tmp_path / "shield.db")
    assert findings == []
    assert state["ledger_rows"] >= 1


def test_a_corrupt_database_is_critical(tmp_path):
    path = tmp_path / "shield.db"
    path.write_bytes(b"not-a-sqlite-database")
    findings, _state = check_database(path)
    assert _ids(findings) == ["GUARDIAN_DATABASE_CORRUPT"]


def test_a_shrinking_ledger_means_someone_deleted_evidence():
    """`maintain()` cố ý không bao giờ prune forensic_ledger. Nó chỉ được
    phép dài ra — ngắn đi là có người xoá bằng chứng."""
    findings = check_ledger_growth({"ledger_rows": 40}, {"ledger_rows": 900})
    assert _ids(findings) == ["GUARDIAN_LEDGER_TRUNCATED"]
    assert findings[0]["severity"] == "critical"


def test_a_growing_ledger_is_normal():
    assert check_ledger_growth({"ledger_rows": 901}, {"ledger_rows": 900}) == []


# --- nhận biết lệnh tắt hợp lệ ---


def test_a_recent_in_app_shutdown_counts_as_authorized(tmp_path):
    path = tmp_path / "shield.db"
    store = Store(path)
    store.add_audit_log("shutdown_agent", {"reason": "mạng trường", "principal": "uid=1000"}, "requested")
    store.close()
    result = authorized_shutdown(path)
    assert result is not None and result["reason"] == "mạng trường"


def test_an_old_shutdown_no_longer_excuses_a_stopped_agent(tmp_path):
    """Nếu không có cửa sổ thời gian, một lần tắt hợp lệ hồi tháng trước sẽ
    che cho mọi vụ giết agent về sau."""
    path = tmp_path / "shield.db"
    store = Store(path)
    store.conn.execute(
        "INSERT INTO audit_log(ts,action_id,params,result) VALUES(?,?,?,?)",
        (time.time() - 86400, "shutdown_agent", json.dumps({"reason": "cũ"}), "requested"),
    )
    store.conn.commit()
    store.close()
    assert authorized_shutdown(path) is None


def test_a_missing_database_is_never_treated_as_authorization(tmp_path):
    """Khi nghi ngờ thì báo động. Xoá DB rồi giết agent không được phép trở
    thành cách tắt Shield trong im lặng."""
    assert authorized_shutdown(tmp_path / "không-có.db") is None


# --- state file ---


def test_state_survives_a_round_trip(tmp_path):
    path = tmp_path / "guardian-state.json"
    write_state(path, {"ledger_rows": 5, "restarts": "1"})
    assert read_state(path)["ledger_rows"] == 5


def test_a_truncated_state_file_does_not_crash_the_next_run(tmp_path):
    path = tmp_path / "guardian-state.json"
    path.write_text("{cụt")
    assert read_state(path) == {}


def test_findings_are_written_into_the_database_directly(tmp_path):
    """Guardian ghi thẳng vào store, không nhờ agent — vì lúc cần ghi nhất
    chính là lúc agent đã chết."""
    path = tmp_path / "shield.db"
    Store(path).close()
    record_findings(path, [{
        "rule_id": "GUARDIAN_AGENT_STOPPED", "severity": "critical",
        "title": "t", "detail": "d", "evidence": {"unit_state": "inactive"},
    }])
    store = Store(path)
    rows = store.conn.execute("SELECT rule_id, subject FROM alerts").fetchall()
    ledger = store.conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()[0]
    store.close()
    assert rows == [("GUARDIAN_AGENT_STOPPED", "shield-guardian")]
    assert ledger >= 1


def test_recording_findings_never_raises_when_the_database_is_gone(tmp_path):
    record_findings(tmp_path / "không-có.db", [{
        "rule_id": "GUARDIAN_AGENT_STOPPED", "severity": "critical",
        "title": "t", "detail": "d", "evidence": {},
    }])


def test_guardian_never_migrates_the_database_it_watches(tmp_path):
    """Guardian ghi phát hiện nhưng KHÔNG được tự migrate.

    Xảy ra thật khi nâng cấp lên 1.1: agent đang khởi động và migrate DB 143 MB,
    guardian chạy cùng lúc, thấy agent chưa lên nên có phát hiện để ghi, mở
    Store chế độ ghi -> cũng bắt đầu migrate và sao lưu chính file đó -> hai
    tiến trình tranh nhau -> `sqlite3.OperationalError: disk I/O error`.
    """
    import sqlite3

    from shield.agent.store import SCHEMA_VERSION, Store

    path = tmp_path / "shield.db"
    Store(path).close()
    # Giả lập database còn ở schema cũ.
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version=3")
    conn.commit()
    conn.close()

    store = Store(path, allow_migration=False)
    try:
        assert store.schema_outdated is True
        version = store.conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == 3, "đã tự migrate dù bị cấm"
    finally:
        store.close()
    assert not list((tmp_path / "backups").glob("*.db")) if (tmp_path / "backups").exists() else True

    # Agent (được phép TƯỜNG MINH) thì vẫn migrate bình thường.
    #
    # `allow_migration=True` phải viết ra: từ 2.0 mặc định là KHÔNG migrate, vì
    # một mặc định "được phép" nghĩa là mọi chỗ gọi mới tự động có quyền đổi
    # schema — và giao diện đã sập vì đúng chuyện đó khi lên 2.0.
    agent_store = Store(path, allow_migration=True)
    try:
        assert agent_store.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    finally:
        agent_store.close()


def test_findings_are_not_written_into_an_outdated_schema(tmp_path, caplog):
    """Schema cũ hơn mã thì bỏ qua việc ghi — phát hiện đã ra journald rồi."""
    import logging
    import sqlite3

    from shield.guardian.__main__ import record_findings

    path = tmp_path / "shield.db"
    from shield.agent.store import Store

    Store(path).close()
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version=3")
    conn.commit()
    conn.close()

    with caplog.at_level(logging.WARNING):
        record_findings(path, [{
            "rule_id": "GUARDIAN_AGENT_STOPPED", "severity": "critical",
            "title": "stopped", "detail": "agent dừng", "evidence": {},
        }])
    # Phát hiện vẫn phải được log ra, và không được ném lỗi.
    assert "GUARDIAN_AGENT_STOPPED" in caplog.text
    assert "schema cũ hơn mã" in caplog.text
    assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0] == 3
