"""Mỗi cạnh giữ neo đầu + tham chiếu MỚI NHẤT, không chỉ 32 cái đầu tiên.

Đo trên DB thật (27–28/09/2026): cạnh chỉ giữ 32 tham chiếu đầu tiên, chúng hết
hạn lưu trữ, và một MAC 6.524 lần quan sát không còn trỏ tới event nào; ~90 %
cạnh thành mồ côi dù hành vi vẫn diễn ra.
"""

from __future__ import annotations

import time

from shield.agent.store import Store
from shield.common.models import Event
from shield.evidence.graph import (EVIDENCE_REFS_ANCHOR, MAX_EVIDENCE_REFS_PER_EDGE, EvidenceGraph,
                                   bounded_refs)


def test_bounded_refs_keeps_the_anchor_and_the_newest():
    refs = [f"event:{i}" for i in range(100)]
    kept = bounded_refs(refs)
    assert len(kept) == MAX_EVIDENCE_REFS_PER_EDGE
    assert kept[:EVIDENCE_REFS_ANCHOR] == refs[:EVIDENCE_REFS_ANCHOR]
    assert kept[EVIDENCE_REFS_ANCHOR:] == refs[-(MAX_EVIDENCE_REFS_PER_EDGE - EVIDENCE_REFS_ANCHOR):]
    assert bounded_refs(["a", "b", "a"]) == ["a", "b"]


def test_a_long_lived_edge_still_points_at_recent_evidence(tmp_path):
    store = Store(tmp_path / "s.db")
    now = time.time()
    ids = []
    for index in range(MAX_EVIDENCE_REFS_PER_EDGE * 3):
        event = Event(now - 1000 + index, "discovery", "host_seen", {"mac": "aa:bb:cc:00:11:22", "ip": "192.0.2.10"})
        store.insert_event(event)
        store.graph_ingest_event(event)
        ids.append(event.event_id)
    refs = [r for (raw,) in store.conn.execute("SELECT evidence_refs FROM graph_edges") for r in __import__("json").loads(raw)]
    assert f"event:{ids[-1]}" in refs, "tham chiếu mới nhất phải có mặt"
    assert f"event:{ids[0]}" in refs, "neo nguồn gốc phải được giữ"


def test_the_edge_survives_expiry_of_its_oldest_evidence(tmp_path):
    store = Store(tmp_path / "s.db")
    now = time.time()
    events = []
    for index in range(MAX_EVIDENCE_REFS_PER_EDGE * 2):
        event = Event(now - 1000 + index, "discovery", "host_seen", {"mac": "aa:bb:cc:00:11:22", "ip": "192.0.2.10"})
        store.insert_event(event)
        store.graph_ingest_event(event)
        events.append(event.event_id)
    half = events[:MAX_EVIDENCE_REFS_PER_EDGE]
    store.conn.execute(f"DELETE FROM events WHERE event_id IN ({','.join('?' * len(half))})", half)
    store.conn.execute("DELETE FROM evidence_objects")
    store.conn.commit()
    result = EvidenceGraph(store.conn).prune()
    assert result["edges_removed"] == 0, "cạnh còn bằng chứng mới không được coi là mồ côi"
