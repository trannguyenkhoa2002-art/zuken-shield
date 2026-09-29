"""Commit rẻ cho telemetry, fsync đầy đủ cho forensic ledger.

Đo trên máy thật 30/09/2026: synchronous=FULL tốn 3,7 ms mỗi commit, ~2,4 commit
mỗi event -> ~9 ms CPU/event, agent 36 % một lõi ở 38 event/giây.
"""

from __future__ import annotations

from shield.agent.store import Store

NORMAL, FULL = 1, 2


def _sync(store: Store) -> int:
    return int(store.conn.execute("PRAGMA synchronous").fetchone()[0])


def test_the_store_runs_wal_with_normal_synchronous(tmp_path):
    store = Store(tmp_path / "s.db")
    assert store.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert _sync(store) == NORMAL


def test_ledger_commits_are_fully_durable_and_restore_normal(tmp_path):
    """Commit chứa bản ghi ledger phải được theo sau bởi một commit ở FULL
    (fsync WAL), và kết nối trở về NORMAL. Ghi ledger TRONG transaction phải
    chạy được — lần sửa đầu đổi pragma trong transaction và làm sập agent."""
    store = Store(tmp_path / "s.db")
    levels = []
    original = store.conn._conn

    class Spy:
        def __getattr__(self, name):
            return getattr(original, name)

        def execute(self, sql, params=()):
            return original.execute(sql, params)

        def _note(self):
            levels.append(int(original.execute("PRAGMA synchronous").fetchone()[0]))

        def commit(self):
            self._note()
            return original.commit()

        def __enter__(self):
            return original.__enter__()

        def __exit__(self, *exc):
            self._note()
            return original.__exit__(*exc)

    store.conn._conn = Spy()
    store.add_forensic_record("test", {"x": 1})
    store.add_audit_log("policy_decision", {"rule_id": "R"}, "alert")   # INSERT trước, ledger sau
    store.conn._conn = original
    assert FULL in levels, levels
    assert _sync(store) == NORMAL
    ok, _bad, _msg = store.verify_forensic_ledger()
    assert ok

def test_one_commit_per_event_and_graph_failure_keeps_the_event(tmp_path, monkeypatch):
    import pytest

    from shield.agent.store import GraphIngestError
    from shield.common.models import Event
    from shield.evidence import graph as graph_module

    store = Store(tmp_path / "s.db")
    commits = []
    original = store.conn._conn

    class Spy:
        def __getattr__(self, name):
            return getattr(original, name)

        def execute(self, sql, params=()):
            return original.execute(sql, params)

        def commit(self):
            commits.append("commit")
            return original.commit()

        def __enter__(self):
            return original.__enter__()

        def __exit__(self, *exc):
            commits.append("commit")
            return original.__exit__(*exc)

    # Mồi: lần đầu gặp một nguồn, sức khoẻ collector được ghi (một lần mỗi 5 s).
    store.ingest_event(Event(0.5, "kernel", "process_exec", {"pid": 1, "exe": "/bin/true"}))
    store.conn._conn = Spy()
    event = Event(1.0, "kernel", "socket_connect",
                  {"pid": 7, "start_ticks": "1", "comm": "x", "remote_ip": "192.0.2.9", "remote_port": 443})
    store.ingest_event(event)
    store.conn._conn = original
    assert len(commits) == 1, commits

    def broken(self, entities, edges):
        raise ValueError("synthetic graph failure")

    monkeypatch.setattr(graph_module.EvidenceGraph, "ingest", broken)
    lost = Event(2.0, "kernel", "socket_connect",
                 {"pid": 8, "start_ticks": "1", "comm": "y", "remote_ip": "192.0.2.10", "remote_port": 443})
    with pytest.raises(GraphIngestError):
        store.ingest_event(lost)
    ids = [r[0] for r in store.conn.execute("SELECT event_id FROM events")]
    assert lost.event_id in ids, "lỗi graph không được làm mất event"
