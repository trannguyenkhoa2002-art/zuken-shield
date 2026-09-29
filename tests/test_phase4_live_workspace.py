"""Giai đoạn 4 — Live Investigation Workspace.

Tiêu chí nghiệm thu:

- Tới 10 tab song song, mỗi tab một bộ lọc (kind, nguồn, IP, MAC, user,
  process, PID, cổng, chuỗi); tab thứ 11 bị từ chối.
- Mỗi tab có Live / Pause / Search / Replay; Pause không làm mất event (giữ
  có trần, tràn thì ĐẾM); Replay đọc lịch sử cũ nhất trước; Search tìm trên cả
  dòng gốc lẫn bản chuẩn hoá.
- Nhóm KHÔNG viết cứng: kind/nguồn và thực thể suy ra từ telemetry, cái mới
  trong 24 giờ được đánh dấu, và "đã thấy từ trước" được nhớ.
- Vòng đời thực thể xuyên suốt: lịch sử của một IP/user vượt trần 7 ngày
  của tìm kiếm thường, qua evidence graph.
- Workspace độc lập với engine: 20 lần SSH sai vẫn xem được TỪNG event gốc,
  và workspace không tạo alert hay incident.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

from shield.agent.bus import Bus
from shield.agent.store import Store
from shield.common.models import Event
from shield.evidence.queries import EvidenceQueries
from shield.security import workspace
from shield.security.workspace import MAX_TABS, TabState, Workspace, WorkspaceFilter, discover_groups
from shield.ui import workspace_view

ROOT = Path(__file__).resolve().parent.parent
DAY = 86400.0


def _ev(kind="ssh_failed_password", source="journal", data=None, raw="", ts=None) -> dict:
    return {"ts": ts or time.time(), "kind": kind, "source": source, "data": data or {}, "raw": raw,
            "event_id": f"e{time.monotonic_ns()}"}


class IpcRecorder:
    def __init__(self):
        self.sent = []

    async def broadcast(self, kind, data):
        pass

    async def send_to(self, client_id, kind, data):
        self.sent.append((kind, data))
        return True


def _handle(store: Store, msg: dict) -> IpcRecorder:
    from shield.agent.__main__ import handle_command

    ipc = IpcRecorder()
    msg = dict(msg, request_id="r1", _peer={"client_id": "c", "uid": 1000, "pid": 1})
    asyncio.run(handle_command(msg, store, None, None, Bus(), ipc, None, None, None, {}, None, None,
                               None, {}))
    return ipc


# --- bộ lọc ----------------------------------------------------------------------


def test_entity_filters_match_any_field_that_carries_the_entity():
    ip = WorkspaceFilter(entity_type="ip", entity_value="203.0.113.7")
    assert ip.matches(_ev(data={"src_ip": "203.0.113.7"}))
    assert ip.matches(_ev(kind="socket_connect", source="kernel", data={"remote_ip": "203.0.113.7"}))
    assert not ip.matches(_ev(data={"src_ip": "203.0.113.8"}))
    mac = WorkspaceFilter(entity_type="mac", entity_value="AA:BB:CC:00:11:22")
    assert mac.matches(_ev(kind="host_seen", data={"mac": "aa:bb:cc:00:11:22"}))
    assert WorkspaceFilter(entity_type="user", entity_value="alice").matches(_ev(data={"user": "alice"}))
    assert WorkspaceFilter(entity_type="process", entity_value="/usr/bin/nc").matches(
        _ev(kind="process_exec", data={"exe": "/usr/bin/nc"}))


def test_text_search_covers_raw_and_normalized():
    flt = WorkspaceFilter(text="invalid user")
    assert flt.matches(_ev(raw="Failed password for invalid user admin"))
    assert WorkspaceFilter(text="51234").matches(_ev(data={"src_port": 51234}))
    assert not flt.matches(_ev(raw="Accepted publickey"))


def test_bad_filters_are_rejected():
    with pytest.raises(ValueError):
        WorkspaceFilter(entity_type="planet", entity_value="mars")
    with pytest.raises(ValueError):
        WorkspaceFilter(entity_type="ip")


# --- tab và workspace --------------------------------------------------------------


def test_ten_parallel_tabs_and_no_eleventh():
    ws = Workspace()
    ids = [ws.open(WorkspaceFilter(entity_type="ip", entity_value=f"10.0.0.{i}")) for i in range(MAX_TABS)]
    assert len(set(ids)) == MAX_TABS == 10
    with pytest.raises(ValueError):
        ws.open(WorkspaceFilter())
    ws.close(ids[0])
    ws.open(WorkspaceFilter())


def test_live_events_are_routed_to_every_matching_tab_only():
    ws = Workspace()
    ssh = ws.open(WorkspaceFilter(kinds=frozenset({"ssh_failed_password"})))
    ip = ws.open(WorkspaceFilter(entity_type="ip", entity_value="203.0.113.7"))
    usb = ws.open(WorkspaceFilter(kinds=frozenset({"usb_added"})))
    assert ws.dispatch(_ev(data={"src_ip": "203.0.113.7"})) == [ssh, ip]
    assert len(ws.tabs[usb].rows) == 0


def test_pause_holds_events_and_resume_flushes_them_in_order():
    tab = TabState(WorkspaceFilter())
    tab.offer(_ev(raw="1"))
    tab.pause()
    tab.offer(_ev(raw="2"))
    tab.offer(_ev(raw="3"))
    assert [e["raw"] for e in tab.rows] == ["1"] and len(tab.pending) == 2
    assert [e["raw"] for e in tab.resume()] == ["2", "3"]
    assert [e["raw"] for e in tab.rows] == ["1", "2", "3"] and tab.mode == "live"


def test_overflow_while_paused_is_counted_not_silent():
    from collections import deque

    tab = TabState(WorkspaceFilter(), pending=deque(maxlen=2))
    tab.pause()
    for index in range(5):
        tab.offer(_ev(raw=str(index)))
    assert tab.dropped_while_paused == 3
    assert "3 dropped while paused" in workspace_view.status_text(tab, "en")


def test_replay_is_oldest_first_and_filtered():
    tab = TabState(WorkspaceFilter(kinds=frozenset({"ssh_failed_password"})))
    now = time.time()
    tab.load_replay([_ev(ts=now, raw="b"), _ev(kind="usb_added", ts=now - 5, raw="x"),
                     _ev(ts=now - 10, raw="a")])
    assert tab.mode == "replay" and [e["raw"] for e in tab.rows] == ["a", "b"]
    tab.offer(_ev(raw="live-during-replay"))
    assert [e["raw"] for e in tab.resume()] == ["live-during-replay"], "replay không làm mất live"


def test_search_within_a_tab():
    tab = TabState(WorkspaceFilter())
    tab.offer(_ev(raw="Failed password for root"))
    tab.offer(_ev(raw="Failed password for alice"))
    assert [e["raw"] for e in tab.search("root")] == ["Failed password for root"]


def test_tab_buffer_is_bounded_and_counts_what_scrolled_out():
    from collections import deque

    tab = TabState(WorkspaceFilter(), rows=deque(maxlen=3))
    for index in range(5):
        tab.offer(_ev(raw=str(index)))
    assert [e["raw"] for e in tab.rows] == ["2", "3", "4"] and tab.evicted == 2


# --- nhóm tự khám phá ----------------------------------------------------------------


def test_groups_come_from_telemetry_and_new_ones_are_flagged(tmp_path):
    store = Store(tmp_path / "s.db")
    now = time.time()
    store.conn.execute(
        "INSERT INTO workspace_kinds (source, kind, first_seen, last_seen) VALUES "
        "('journal', 'ssh_failed_password', ?, ?)", (now - 30 * DAY, now - 30 * DAY))
    store.conn.commit()
    for index in range(3):
        store.insert_event(Event(now - index, "journal", "ssh_failed_password", {"src_ip": "203.0.113.7"}))
    store.insert_event(Event(now, "endpoint", "usb_added", {"vendor": "x"}))
    store.insert_event(Event(now, "auditd", "process_exec", {"exe": "/usr/bin/nc", "pid": 7}))
    groups = discover_groups(store.conn, now)
    by_label = {g["label"]: g for g in groups}
    assert by_label["ssh_failed_password @ journal"]["count"] == 3
    assert by_label["ssh_failed_password @ journal"]["new"] is False, "đã thấy từ 30 ngày trước"
    assert by_label["usb_added @ endpoint"]["new"] is True
    assert by_label["process /usr/bin/nc"]["filter"] == {
        "kinds": [], "sources": [], "entity_type": "process", "entity_value": "/usr/bin/nc", "text": ""}
    again = {g["label"]: g for g in discover_groups(store.conn, now + 2 * DAY)}
    assert again.get("usb_added @ endpoint") is None or again["usb_added @ endpoint"]["new"] is False


def test_entity_groups_open_tabs_that_actually_match_live_events(tmp_path):
    store = Store(tmp_path / "s.db")
    event = Event(time.time(), "journal", "ssh_login", {"user": "alice", "src_ip": "203.0.113.7"})
    store.insert_event(event)
    store.graph_ingest_event(event)
    groups = discover_groups(store.conn)
    for kind in ("user", "ip"):
        group = next(g for g in groups if g["group"] == kind)
        flt = WorkspaceFilter.from_dict(group["filter"])
        assert flt.matches(event.to_dict()), f"nhóm {kind} mở ra một tab không khớp gì"


# --- vòng đời thực thể -------------------------------------------------------------------


def test_entity_history_spans_beyond_the_seven_day_search_window(tmp_path):
    store = Store(tmp_path / "s.db")
    now = time.time()
    for age_days in (40, 10, 0):
        event = Event(now - age_days * DAY, "journal", "ssh_login",
                      {"user": "alice", "src_ip": "203.0.113.7"}, raw=f"Accepted for alice {age_days}d")
        store.insert_event(event)
        store.graph_ingest_event(event)
    history = EvidenceQueries(store.conn).entity_history("ip", "203.0.113.7")
    assert [e["raw"] for e in history["events"]] == [
        "Accepted for alice 40d", "Accepted for alice 10d", "Accepted for alice 0d"]
    assert history["summary"]["first_seen"] <= now - 39 * DAY
    user = EvidenceQueries(store.conn).entity_history("user", "alice")
    assert len(user["events"]) == 3 and user["summary"]["known"] is True


def test_unknown_entities_say_so(tmp_path):
    history = EvidenceQueries(Store(tmp_path / "s.db").conn).entity_history("ip", "198.51.100.99")
    assert history["events"] == [] and history["summary"]["known"] is False


# --- IPC ------------------------------------------------------------------------------------


def test_ipc_history_for_an_entity_uses_the_lifetime_path(tmp_path):
    store = Store(tmp_path / "s.db")
    old = Event(time.time() - 20 * DAY, "journal", "ssh_login", {"user": "bob", "src_ip": "203.0.113.9"})
    store.insert_event(old)
    store.graph_ingest_event(old)
    ipc = _handle(store, {"cmd": "workspace_history", "tab_id": "tab-1", "window_s": 3600,
                          "filter": {"entity_type": "ip", "entity_value": "203.0.113.9"}})
    kind, data = ipc.sent[0]
    assert kind == "workspace_history" and data["tab_id"] == "tab-1"
    assert [e["event_id"] for e in data["events"]] == [old.event_id]
    assert data["summary"]["known"] is True


def test_twenty_ssh_failures_remain_individually_visible(tmp_path):
    """Engine có thể gộp chúng thành MỘT incident; workspace vẫn thấy TỪNG dòng gốc."""
    store = Store(tmp_path / "s.db")
    now = time.time()
    for index in range(20):
        store.insert_event(Event(now - index, "journal", "ssh_failed_password", {"src_ip": "203.0.113.7"},
                                 raw=f"Failed password #{index} from 203.0.113.7"))
    ipc = _handle(store, {"cmd": "workspace_history", "tab_id": "t", "window_s": 3600,
                          "filter": {"kinds": ["ssh_failed_password"], "sources": ["journal"]}})
    events = ipc.sent[0][1]["events"]
    assert len(events) == 20
    assert events[0]["raw"] == "Failed password #19 from 203.0.113.7", "cũ nhất trước"
    assert store.recent_alerts() == [], "workspace không tạo alert"


def test_ipc_groups_and_bad_filters(tmp_path):
    store = Store(tmp_path / "s.db")
    store.insert_event(Event(time.time(), "journal", "usb_new", {"message": "x"}))
    assert _handle(store, {"cmd": "workspace_groups"}).sent[0][0] == "workspace_groups"
    bad = _handle(store, {"cmd": "workspace_history", "filter": {"entity_type": "planet", "entity_value": "x"}})
    assert bad.sent[0][0] == "command_error"


def test_the_workspace_never_creates_alerts_or_incidents():
    source = (ROOT / "shield/security/workspace.py").read_text(encoding="utf-8")
    for forbidden in ("insert_alert", "open_or_update_incident", "alert_bus", "GrayZoneStore"):
        assert forbidden not in source


# --- giao diện thật (bỏ qua nếu máy không dựng được Qt) ----------------------------------------


def test_the_qt_workspace_opens_tabs_pauses_replays_and_searches(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    widgets = pytest.importorskip("PySide6.QtWidgets")
    try:
        app = widgets.QApplication.instance() or widgets.QApplication([])
    except Exception as exc:  # noqa: BLE001 — máy CI không có libEGL
        pytest.skip(f"Qt unavailable: {exc}")
    from shield.ui.__main__ import LiveWorkspaceTab

    class Client:
        def __init__(self):
            self.sent = []

        def send_command(self, msg):
            self.sent.append(msg)
            return True

    client = Client()
    tab = LiveWorkspaceTab(client)
    tab_id = tab.open_filter(WorkspaceFilter(kinds=frozenset({"ssh_failed_password"})))
    view = tab.views[tab_id]
    tab.on_live_event(_ev(raw="Failed password for root"))
    assert view.table.rowCount() == 1
    view.live_btn.setChecked(False)
    tab.on_live_event(_ev(raw="while paused"))
    assert view.table.rowCount() == 1 and len(view.state.pending) == 1
    view._replay()
    assert client.sent[-1]["cmd"] == "workspace_history"
    tab.on_history({"tab_id": tab_id, "events": [_ev(raw="old A", ts=1.0), _ev(raw="old B", ts=2.0)],
                    "summary": {}})
    assert view.table.rowCount() == 2 and view.state.mode == "replay"
    assert not view.live_btn.isChecked(), "đang xem lại mà nút vẫn báo Live"
    view.search_box.setText("old B")
    assert view.table.rowCount() == 1
    view.search_box.setText("")
    view.live_btn.setChecked(True)
    assert view.state.mode == "live" and view.table.rowCount() == 3
    tab.on_groups([{"label": "usb_added @ endpoint", "count": 2, "new": True,
                    "filter": {"kinds": ["usb_added"]}}])
    assert "NEW" in tab.group_list.item(0).text()
    app.processEvents()


def test_workspace_module_is_registered_in_the_schema(tmp_path):
    store = Store(tmp_path / "s.db")
    tables = {r[0] for r in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "workspace_kinds" in tables
    assert workspace.MAX_TABS == 10


def test_history_keys_match_the_workspace_filter_keys():
    from shield.evidence.queries import ENTITY_KEYS_FOR_HISTORY

    for kind, keys in ENTITY_KEYS_FOR_HISTORY.items():
        assert keys == workspace.ENTITY_KEYS[kind], kind


def test_recent_events_are_found_even_when_graph_refs_point_only_at_expired_ones(tmp_path):
    """Đo trên DB thật: MAC 6.524 lần quan sát, 0 event qua graph — graph giữ 32
    tham chiếu ĐẦU TIÊN mỗi cạnh, và chúng đã hết hạn lưu trữ."""
    from shield.evidence.graph import MAX_EVIDENCE_REFS_PER_EDGE

    store = Store(tmp_path / "s.db")
    now = time.time()
    early = []
    for index in range(MAX_EVIDENCE_REFS_PER_EDGE + 5):
        event = Event(now - 30 * DAY + index, "discovery", "host_seen",
                      {"mac": "aa:bb:cc:00:11:22", "ip": "192.0.2.10"})
        store.insert_event(event)
        store.graph_ingest_event(event)
        early.append(event.event_id)
    placeholders = ",".join("?" * len(early))
    store.conn.execute(f"DELETE FROM events WHERE event_id IN ({placeholders})", early)
    recent = Event(now - 60, "discovery", "host_seen", {"mac": "aa:bb:cc:00:11:22", "ip": "192.0.2.10"},
                   raw="arp-scan: 192.0.2.10 aa:bb:cc:00:11:22")
    store.insert_event(recent)
    store.graph_ingest_event(recent)
    # Mô phỏng cạnh do BẢN CŨ ghi: chỉ giữ tham chiếu đầu tiên (đã hết hạn).
    store.conn.execute("UPDATE graph_edges SET evidence_refs=?", (json.dumps([f"event:{e}" for e in early[:32]]),))
    store.conn.commit()
    history = EvidenceQueries(store.conn).entity_history("mac", "AA:BB:CC:00:11:22")
    assert [e["event_id"] for e in history["events"]] == [recent.event_id]
    assert history["summary"]["from_recent_scan"] == 1 and history["summary"]["from_graph"] == 0
    assert history["summary"]["observations"] >= MAX_EVIDENCE_REFS_PER_EDGE


def test_the_first_discovery_run_does_not_call_everything_new(tmp_path):
    """Máy thật 29/09/2026: lần đầu mọi kind hiện "NEW", kể cả file_write có từ hàng tháng."""
    store = Store(tmp_path / "s.db")
    now = time.time()
    store.insert_event(Event(now - 60, "kernel", "file_write", {"exe": "/usr/bin/bash"}))
    first = {g["label"]: g for g in discover_groups(store.conn, now)}
    assert first["file_write @ kernel"]["new"] is False
    store.insert_event(Event(now + 120, "endpoint", "usb_added", {"vendor": "x"}))
    later = {g["label"]: g for g in discover_groups(store.conn, now + 180)}
    assert later["usb_added @ endpoint"]["new"] is True, "kind xuất hiện SAU khi bắt đầu theo dõi là mới"
    assert later["file_write @ kernel"]["new"] is False
