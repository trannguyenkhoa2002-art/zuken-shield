"""Giai đoạn 3 — giữ CẢ dòng log gốc lẫn event đã chuẩn hoá.

Tiêu chí nghiệm thu:

- journal, auditd, syslog và probe đều mang dòng gốc; event tổng hợp (không có
  dòng gốc) để trống và màn hình nói rõ là không có, không dựng lại.
- Bí mật bị che TRƯỚC khi event rời collector (live IPC, xuất log, DB), và
  dòng gốc bị cắt theo cấu hình; 0 = tắt lưu raw.
- Thêm raw không đổi danh tính bằng chứng (content_hash, event_id) và không
  đổi bản đã chuẩn hoá.
- Raw đi hết đường: Event -> SQLite -> Expert Evidence -> dòng hiển thị, và
  database cũ được migrate với raw rỗng.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time

from shield.agent.bus import Bus
from shield.agent.collectors import journal
from shield.agent.collectors.auditd import parse_audit_message
from shield.agent.collectors.log_ingest import normalize_record
from shield.agent.collectors.syslog_server import SyslogCollector
from shield.agent.store import Store
from shield.common import models
from shield.common.models import Event
from shield.evidence.queries import EvidenceQueries
from shield.ui.evidence_view import evidence_detail_rows

SSH_LINE = "Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2"


def _journal_events(message: str, identifier: str = "sshd") -> list[Event]:
    bus = Bus()
    queue = bus.subscribe()
    entry = {"SYSLOG_IDENTIFIER": identifier, "MESSAGE": message}
    asyncio.run(journal._handle_line(bus, json.dumps(entry).encode()))
    out = []
    while not queue.empty():
        out.append(queue.get_nowait())
    return out


# --- nguồn nào có dòng gốc ------------------------------------------------------


def test_journal_events_keep_the_original_message_next_to_the_normalized_fields():
    (event,) = _journal_events(SSH_LINE)
    assert event.kind == "ssh_failed_password"
    assert event.raw == SSH_LINE
    assert event.data["src_ip"] == "203.0.113.7", "bản chuẩn hoá vẫn nguyên"


def test_auditd_records_keep_the_audit_line():
    line = ('type=SYSCALL msg=audit(1.0:42): arch=c000003e syscall=59 success=yes pid=10 ppid=1 '
            'uid=0 auid=1000 comm="bash" exe="/usr/bin/bash"')
    event = parse_audit_message(line)
    assert event is not None and event.raw == line
    assert event.data["exe"] == "/usr/bin/bash"


def test_syslog_keeps_the_datagram_as_sent():
    bus = Bus(max_queue_size=8)
    queue = bus.subscribe()
    collector = SyslogCollector(bus, allowlist="192.168.1.0/24")
    line = b"<34>Oct 11 22:14:15 router su[1234]: 'su root' failed for admin\n"
    assert asyncio.run(collector.handle_payload(line, "192.168.1.1")) is True
    assert queue.get_nowait().raw == "<34>Oct 11 22:14:15 router su[1234]: 'su root' failed for admin"


def test_probe_raw_is_accepted_only_as_a_string():
    base = {"source": "probe.journal", "kind": "ssh_auth_failure", "ts": time.time(), "data": {"src_ip": "x"}}
    assert normalize_record(dict(base, raw=SSH_LINE), "probe-1", "10.0.0.2").raw == SSH_LINE
    assert normalize_record(dict(base, raw={"x": 1}), "probe-1", "10.0.0.2").raw == ""


def test_synthesised_events_have_no_raw_and_the_viewer_says_so(tmp_path):
    store = Store(tmp_path / "s.db")
    event = Event(time.time(), "endpoint", "process_started", {"pid": 7})
    store.insert_event(event)
    detail = EvidenceQueries(store.conn).get_event(event.event_id)
    assert detail["raw_retained"] is False and detail["raw"] == ""
    rows = evidence_detail_rows(detail, lambda key: key, str)
    assert ("evidence.raw_not_retained", "", "raw") in rows


# --- che bí mật và giới hạn -------------------------------------------------------


def test_secrets_are_redacted_before_the_event_leaves_the_collector(tmp_path):
    (event,) = _journal_events("Accepted password for root from 203.0.113.7 port 22 ssh2 password=hunter2")
    assert "hunter2" not in event.raw
    assert "hunter2" not in json.dumps(event.to_dict()), "luồng live/xuất log dùng to_dict"
    store = Store(tmp_path / "s.db")
    store.insert_event(event)
    stored = store.conn.execute("SELECT raw FROM events WHERE event_id=?", (event.event_id,)).fetchone()[0]
    assert "hunter2" not in stored


def test_raw_is_capped_and_can_be_disabled(monkeypatch):
    monkeypatch.setattr(models, "RAW_MAX_CHARS", 32)
    assert len(Event(0, "journal", "x", {}, raw="a" * 500).raw) == 32
    monkeypatch.setattr(models, "RAW_MAX_CHARS", 0)
    assert Event(0, "journal", "x", {}, raw="kept?").raw == ""


def test_raw_does_not_change_the_identity_of_evidence():
    plain = Event(1.0, "journal", "ssh_login", {"user": "a"})
    with_raw = Event(1.0, "journal", "ssh_login", {"user": "a"}, raw="Accepted publickey for a")
    assert plain.content_hash_ == with_raw.content_hash_


# --- đi hết đường ống ---------------------------------------------------------------


def test_raw_and_normalized_are_both_served_by_expert_evidence(tmp_path):
    store = Store(tmp_path / "s.db")
    (event,) = _journal_events(SSH_LINE)
    store.insert_event(event)
    detail = EvidenceQueries(store.conn).get_event(event.event_id)
    assert detail["raw_retained"] is True
    assert detail["raw"] == SSH_LINE
    assert detail["data"]["src_ip"] == "203.0.113.7"
    rows = evidence_detail_rows(detail, lambda key: key, str)
    assert ("evidence.raw_available", SSH_LINE, "raw") in rows
    found = EvidenceQueries(store.conn).search_events(
        start_time=time.time() - 60, end_time=time.time() + 60, kind="ssh_failed_password")
    assert found["events"] and found["events"][0]["raw"] == SSH_LINE


def test_event_round_trip_keeps_raw():
    event = Event(1.0, "journal", "ssh_login", {"user": "a"}, raw="Accepted publickey for a")
    assert Event.from_dict(json.loads(json.dumps(event.to_dict()))).raw == "Accepted publickey for a"


def test_an_old_events_table_migrates_with_empty_raw(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
            source TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
        INSERT INTO events (ts, source, kind, data) VALUES (1, 'journal', 'ssh_login', '{}');
    """)
    conn.commit()
    conn.close()
    store = Store(path, allow_migration=True)
    assert store.conn.execute("SELECT raw FROM events").fetchone()[0] == ""


def test_raw_is_trimmed_together_with_its_event(tmp_path):
    """Raw nằm TRONG dòng event: cắt event theo trần dung lượng thì raw đi theo,
    không có kho raw riêng nào lớn lên ngoài tầm kiểm soát."""
    store = Store(tmp_path / "s.db")
    for index in range(50):
        store.insert_event(Event(time.time() - 400 * 86400, "journal", "ssh_login", {"i": index},
                                 raw="x" * 200))
    store.maintain(event_days=30, alert_days=90, snapshot_days=30)
    assert store.conn.execute("SELECT COUNT(*) FROM events WHERE raw != ''").fetchone()[0] == 0


def test_normalized_message_fields_are_redacted_too(tmp_path):
    """Lỗi có từ trước giai đoạn 3: `data.message` nguyên văn đi thẳng vào DB.

    README hứa "Secrets are redacted before anything is stored"; với journal,
    syslog và probe thì điều đó không đúng cho tới bản sửa này.
    """
    (event,) = _journal_events("Failed password for admin from 203.0.113.7 port 22 ssh2 token=abc123secret")
    assert "abc123secret" not in json.dumps(event.data)
    bus = Bus(max_queue_size=8)
    queue = bus.subscribe()
    collector = SyslogCollector(bus, allowlist="192.168.1.0/24")
    asyncio.run(collector.handle_payload(b"<34>Oct 11 22:14:15 router app: login password=hunter2", "192.168.1.1"))
    syslog_event = queue.get_nowait()
    assert "hunter2" not in json.dumps(syslog_event.data) and "hunter2" not in syslog_event.raw
    probe = normalize_record({"source": "probe.journal", "kind": "log_line", "ts": time.time(),
                              "data": {"line": "curl -H token=abc123secret"}}, "p1", "10.0.0.2")
    assert "abc123secret" not in json.dumps(probe.data)
