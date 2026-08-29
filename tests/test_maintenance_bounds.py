"""Bảo trì phải TIẾN ĐỀU, không phải xong trong một lượt.

Sự cố có thật, trên máy production, ngay sau khi nâng cấp lên 3.0.0a1: agent
khởi động, chạy 94 giây rồi bị systemd giết bằng SIGABRT — bốn lần liên tiếp,
sau đó service nằm ở trạng thái `failed` và không tự dậy lại nữa. Máy mất hoàn
toàn lớp phòng thủ cho tới khi có người chạy tay `systemctl reset-failed`.

Nguyên nhân không phải vòng lặp sự kiện bị chặn — `store.maintain` đã chạy
trong `asyncio.to_thread` từ trước. Nguyên nhân là CÁI KHOÁ: watchdog chứng
minh store còn sống bằng `store.get_baseline(...)`, nên nó xếp hàng sau đúng
cái khoá mà lượt bảo trì đang giữ. Đo trên database production (1,59 triệu
event, 1,24 triệu cạnh): một vòng "xoá 50k + dọn graph toàn bảng" mất 9,6
giây, và vòng lặp cũ chạy tới 40 vòng — gần 400 giây.

Nên các bài dưới đây kiểm đúng một điều: KHÔNG lượt nào được phép chạy tới khi
hết backlog.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shield.agent.store import (GRAPH_PRUNE_CURSOR_KEY, GRAPH_PRUNE_MAX_EDGES,
                                RETENTION_DELETE_LIMIT, SIZE_CAP_MAX_BATCHES, Store)
from shield.common.models import Alert, Event
from shield.evidence.graph import EvidenceGraph

OLD = time.time() - 400 * 86400


def _store(tmp_path):
    return Store(tmp_path / "s.db")


def _events(store, count, *, ts=OLD):
    rows = [Event(ts + index, "test", "process_exec", {"i": index})
            for index in range(count)]
    for event in rows:
        store.insert_event(event)
    store.conn.commit()
    return rows


def _edges(store, count):
    """Cạnh THẬT qua API graph, trỏ tới event thật rồi xoá event đi.

    Dựng bằng `upsert_edge` chứ không `INSERT` tay: bảng có ràng buộc mà một
    hàng viết tay dễ bỏ sót, và `upsert_edge` còn từ chối cạnh có bằng chứng
    không tồn tại — nên phải có event thật trước. Xoá event sau đúng bằng việc
    lưu trữ làm, và đó chính là thứ sinh ra cạnh mồ côi cần dọn.
    """
    from shield.evidence.models import Edge, Entity

    graph = EvidenceGraph(store.conn)
    events = _events(store, count)
    with store.conn:
        for index, event in enumerate(events):
            ref = f"event:{event.event_id}"
            graph.record_evidence(ref, ts=OLD)
            src = graph.upsert_entity(Entity("process", f"src-{index:07d}",
                                             first_seen=OLD, last_seen=OLD))
            dst = graph.upsert_entity(Entity("process", f"dst-{index:07d}",
                                             first_seen=OLD, last_seen=OLD))
            graph.upsert_edge(Edge(src, "spawned", dst, (ref,), "local", "test",
                                   first_seen=OLD, last_seen=OLD))
        # Event biến mất -> mọi cạnh thành mồ côi, đúng tình huống cần dọn.
        store.conn.execute("DELETE FROM events")
        store.conn.execute("DELETE FROM evidence_objects")
    return graph


# --- trần theo lô -------------------------------------------------------


def test_one_pass_never_drains_an_unlimited_backlog(tmp_path):
    """Bài kiểm sẽ ĐỎ với mã cũ: vòng lặp cũ chạy tới khi hết backlog."""
    store = _store(tmp_path)
    _events(store, RETENTION_DELETE_LIMIT + 500)
    before = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    result = store.maintain(event_days=30, alert_days=90, snapshot_days=30)

    assert result["events_deleted"] == RETENTION_DELETE_LIMIT
    remaining = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert remaining == before - RETENTION_DELETE_LIMIT
    assert result["more_work"] is True, "còn backlog mà không báo còn việc"


def test_repeated_passes_converge(tmp_path):
    store = _store(tmp_path)
    _events(store, RETENTION_DELETE_LIMIT + 500)

    passes = 0
    while True:
        result = store.maintain(event_days=30, alert_days=90, snapshot_days=30)
        passes += 1
        assert passes <= 10, "không hội tụ"
        if not result["more_work"]:
            break

    assert passes >= 2, "hội tụ trong một lượt nghĩa là trần không có tác dụng"
    assert store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_a_second_pass_continues_from_what_the_first_left(tmp_path):
    store = _store(tmp_path)
    _events(store, RETENTION_DELETE_LIMIT + 200)
    store.maintain(event_days=30, alert_days=90, snapshot_days=30)
    mid = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert mid == 200
    store.maintain(event_days=30, alert_days=90, snapshot_days=30)
    assert store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_the_size_cap_deletes_at_most_one_batch_per_pass(tmp_path):
    """`SIZE_CAP_MAX_BATCHES` là trần, không phải gợi ý."""
    store = _store(tmp_path)
    _events(store, 300, ts=time.time())          # còn hạn, chỉ trần dung lượng cắt được
    removed = store._enforce_size_cap(1, batch=50)     # trần 1 byte: luôn "quá trần"
    assert removed <= 50 * SIZE_CAP_MAX_BATCHES
    assert removed == 50, removed


# --- dọn graph theo lát -------------------------------------------------


def test_the_graph_prune_stops_at_its_bound(tmp_path):
    store = _store(tmp_path)
    _edges(store, 120)
    result = EvidenceGraph(store.conn).prune(max_edges=50)
    assert result["edges_scanned"] == 50
    assert result["complete"] is False
    assert result["next_cursor"], "dừng giữa chừng mà không để lại con trỏ"


def test_the_graph_prune_resumes_and_eventually_covers_everything(tmp_path):
    store = _store(tmp_path)
    _edges(store, 120)
    graph = EvidenceGraph(store.conn)

    seen, cursor, rounds = 0, "", 0
    while True:
        result = graph.prune(max_edges=50, after=cursor)
        seen += result["edges_scanned"]
        cursor = result["next_cursor"]
        rounds += 1
        assert rounds <= 10
        if result["complete"]:
            break
    assert seen == 120, f"quét {seen}/120 cạnh"
    assert store.conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0] == 0


def test_the_cursor_survives_a_restart(tmp_path):
    store = _store(tmp_path)
    _edges(store, 120)
    store._prune_graph_slice(max_edges=50)
    saved = store.get_baseline(GRAPH_PRUNE_CURSOR_KEY)
    assert saved

    reborn = Store(tmp_path / "s.db")
    assert reborn.get_baseline(GRAPH_PRUNE_CURSOR_KEY) == saved


def test_a_partial_prune_leaves_the_graph_consistent(tmp_path):
    """Bỏ dở giữa chừng KHÔNG được để lại node treo hay cạnh mất bằng chứng."""
    store = _store(tmp_path)
    _edges(store, 120)
    store._prune_graph_slice(max_edges=50)

    dangling = store.conn.execute(
        "SELECT COUNT(*) FROM graph_entities WHERE entity_id NOT IN "
        "(SELECT src_id FROM graph_edges UNION SELECT dst_id FROM graph_edges)"
    ).fetchone()[0]
    assert dangling == 0, f"{dangling} node treo sau lượt dọn dở"
    assert store.conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert store.conn.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"


def test_an_unbounded_prune_still_works_for_callers_that_want_one(tmp_path):
    store = _store(tmp_path)
    _edges(store, 120)
    result = EvidenceGraph(store.conn).prune()
    assert result["complete"] is True
    assert result["edges_scanned"] == 120


# --- bất biến lưu trữ ---------------------------------------------------


def test_maintenance_never_touches_the_forensic_ledger(tmp_path):
    store = _store(tmp_path)
    _events(store, 100)
    before = store.conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()[0]
    for _ in range(3):
        store.maintain(event_days=30, alert_days=90, snapshot_days=30,
                       database_max_bytes=1)
    after = store.conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()[0]
    assert after >= before


def test_the_database_stays_healthy_after_every_partial_pass(tmp_path):
    store = _store(tmp_path)
    _events(store, RETENTION_DELETE_LIMIT + 300)
    _edges(store, 200)
    for _ in range(4):
        store.maintain(event_days=30, alert_days=90, snapshot_days=30,
                       database_max_bytes=1)
        assert store.conn.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
        assert store.conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_the_bounds_are_real_numbers_not_disabled(tmp_path):
    """Một trần đặt bằng 0 hay vô hạn là một trần không tồn tại."""
    assert 0 < SIZE_CAP_MAX_BATCHES <= 4
    assert 0 < RETENTION_DELETE_LIMIT <= 100_000
    assert 0 < GRAPH_PRUNE_MAX_EDGES <= 100_000


def test_the_default_size_cap_policy_is_unchanged():
    """Bản sửa này là LỊCH TRÌNH, không phải chính sách lưu trữ."""
    from shield.security.health import RetentionPolicy

    policy = RetentionPolicy.from_env()
    assert policy.database_max_bytes == 2048 * 1024 ** 2


def test_a_large_backlog_is_not_drained_by_a_single_invocation(tmp_path):
    """Bài này KHÔNG nhập hằng số mới, nên nó chạy được trên cả mã cũ.

    Trên mã cũ nó đỏ: `DELETE FROM events WHERE ts < ?` không có `LIMIT`, nên
    một lời gọi xoá sạch backlog — và đúng hành vi đó, cộng với vòng lặp trần
    dung lượng 40 lô, đã giữ khoá database gần 400 giây và làm systemd giết
    agent bốn lần trên máy thật.
    """
    store = Store(tmp_path / "s.db")
    backlog = 120_000
    rows = [Event(OLD + index, "test", "process_exec", {"i": index})
            for index in range(backlog)]
    for event in rows:
        store.insert_event(event)
    store.conn.commit()

    started = time.perf_counter()
    result = store.maintain(event_days=30, alert_days=90, snapshot_days=30)
    elapsed = time.perf_counter() - started

    remaining = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert remaining > 0, "một lượt đã xoá sạch backlog — trần không có tác dụng"
    assert result["events_deleted"] <= backlog // 2

    # Watchdog production: ping 45 s, timeout 90 s. Một lượt phải nhỏ hơn nhiều.
    assert elapsed < 20.0, f"một lượt mất {elapsed:.1f}s — quá gần biên watchdog"
