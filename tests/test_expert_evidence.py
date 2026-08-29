"""Expert Evidence — đường kiểm chứng độc lập, không có AI.

Câu hỏi mà màn hình này tồn tại để trả lời: *"Tôi không tin kết luận của
Shield. Cho tôi xem bằng chứng."* Nếu để trả lời được câu đó mà phải gọi một
model, thì nó không còn là kiểm chứng độc lập nữa.
"""

from __future__ import annotations

import ast
import json
import sqlite3
import time
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.common.models import Event, new_event_id
from shield.evidence.queries import MAX_WINDOW_S, EvidenceQueries
from shield.ui.evidence_view import event_subject, event_summary, evidence_detail_rows

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "s.db", allow_migration=True)


def _seed(store, count=5, base=1_000_000.0, kind="process_exec", source="kernel"):
    ids = []
    for index in range(count):
        event = Event(base + index, source, kind,
                      {"pid": 100 + index, "exe": "/bin/sh", "token": "hunter2"},
                      event_id=new_event_id())
        store.insert_event(event)
        ids.append(event.event_id)
    return ids


def _q(store):
    return EvidenceQueries(store.conn, caller="test")


# --- cửa sổ thời gian bắt buộc và có trần ---


def test_a_search_without_a_time_window_is_refused(store):
    with pytest.raises(TypeError):
        _q(store).search_events()


def test_an_inverted_window_is_refused(store):
    with pytest.raises(ValueError, match="lớn hơn"):
        _q(store).search_events(start_time=100.0, end_time=50.0)


def test_a_window_wider_than_the_cap_is_refused(store):
    """Bảng events trên máy thật đã 1,85 triệu dòng và chỉ lớn thêm. Một câu
    truy vấn không ràng buộc thời gian là câu quét toàn bảng đang chờ tới lượt."""
    now = time.time()
    with pytest.raises(ValueError, match="vượt trần"):
        _q(store).search_events(start_time=now - MAX_WINDOW_S - 60, end_time=now)


def test_the_page_size_has_a_hard_cap(store):
    _seed(store, count=30)
    result = _q(store).search_events(start_time=999_000, end_time=1_001_000, limit=10 ** 9)
    assert len(result["events"]) <= 500


# --- con trỏ ---


def test_the_cursor_is_stable_when_timestamps_collide(store):
    """Nhiều event có thể mang cùng một mốc thời gian. Con trỏ chỉ dựa trên
    `ts` sẽ hoặc bỏ sót hoặc lặp lại đúng những dòng đó."""
    for index in range(10):
        store.insert_event(Event(1_000_000.0, "kernel", "process_exec",
                                 {"n": index}, event_id=new_event_id()))
    queries = _q(store)
    first = queries.search_events(start_time=999_000, end_time=1_001_000, limit=4)
    second = queries.search_events(start_time=999_000, end_time=1_001_000, limit=4,
                                   cursor=first["next_cursor"])
    third = queries.search_events(start_time=999_000, end_time=1_001_000, limit=4,
                                  cursor=second["next_cursor"])
    seen = [e["row_id"] for page in (first, second, third) for e in page["events"]]
    assert len(seen) == len(set(seen)) == 10, "con trỏ bỏ sót hoặc lặp dòng"
    assert seen == sorted(seen, reverse=True), "thứ tự không tất định"


def test_a_malformed_cursor_is_refused_not_ignored(store):
    """Bỏ qua một con trỏ hỏng nghĩa là âm thầm trả về trang ĐẦU trong khi
    người gọi tưởng mình đang đi tiếp."""
    _seed(store)
    for bad in ("rác", "1:2:3", "abc:def", ":", "1.0:"):
        with pytest.raises(ValueError, match="cursor"):
            _q(store).search_events(start_time=999_000, end_time=1_001_000, cursor=bad)


def test_no_cursor_when_the_page_is_not_full(store):
    _seed(store, count=3)
    result = _q(store).search_events(start_time=999_000, end_time=1_001_000, limit=100)
    assert result["next_cursor"] == ""


# --- lọc ---


def test_an_unknown_filter_field_is_refused(store):
    """Tên trường tự do đi thẳng vào biểu thức SQL là một bề mặt tấn công, và
    một tên sai thì im lặng trả về rỗng — trông y hệt "không có gì xảy ra"."""
    with pytest.raises(ValueError, match="không được phép"):
        _q(store).search_events(start_time=999_000, end_time=1_001_000,
                                filters={"'; DROP TABLE events;--": 1})


def test_filters_narrow_the_result(store):
    _seed(store, count=5)
    result = _q(store).search_events(start_time=999_000, end_time=1_001_000,
                                     filters={"pid": 102})
    assert [e["data"]["pid"] for e in result["events"]] == [102]


def test_kind_and_source_filters_work(store):
    _seed(store, count=3, kind="process_exec", source="kernel")
    _seed(store, count=2, base=1_000_100.0, kind="file_write", source="kernel")
    queries = _q(store)
    assert len(queries.search_events(start_time=999_000, end_time=1_001_000,
                                     kind="file_write")["events"]) == 2
    assert len(queries.search_events(start_time=999_000, end_time=1_001_000,
                                     source="endpoint")["events"]) == 0


# --- che bí mật ---


def test_search_results_go_through_the_shared_redactor(store):
    """"Raw" không có nghĩa là bỏ qua bảo vệ bí mật."""
    from shield.common.secrets import REDACTED

    _seed(store, count=1)
    event, = _q(store).search_events(start_time=999_000, end_time=1_001_000)["events"]
    assert event["data"]["token"] == REDACTED
    assert "hunter2" not in json.dumps(event)


def test_get_event_goes_through_the_shared_redactor(store):
    from shield.common.secrets import REDACTED

    event_id, = _seed(store, count=1)
    assert _q(store).get_event(event_id)["data"]["token"] == REDACTED


def test_the_read_path_does_not_define_its_own_redaction():
    tree = ast.parse((ROOT / "shield" / "evidence" / "queries.py").read_text(encoding="utf-8"))
    modules = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert "shield.common.secrets" in modules


# --- nhật ký truy vấn ---


def test_every_search_leaves_an_audit_entry(store):
    _seed(store)
    queries = _q(store)
    queries.search_events(start_time=999_000, end_time=1_001_000, kind="process_exec")
    entry = queries.audit.entries[-1]
    assert entry["query"] == "search_events"
    assert entry["caller"] == "test"
    assert entry["rows"] == 5
    assert entry["params"]["kind"] == "process_exec"


def test_a_refused_query_is_also_audited(store):
    queries = _q(store)
    with pytest.raises(ValueError):
        queries.search_events(start_time=999_000, end_time=1_001_000, cursor="rác")
    # Từ chối trước khi chạy: không có dòng nhật ký nào của câu KHÔNG chạy, và
    # đó là đúng — nhật ký ghi việc ĐỌC, không ghi việc gõ sai.
    assert not any(e["query"] == "search_events" for e in queries.audit.entries)


def test_the_audit_records_scope_not_content(store):
    _seed(store, count=1)
    queries = _q(store)
    queries.search_events(start_time=999_000, end_time=1_001_000)
    assert "hunter2" not in json.dumps(queries.audit.entries, default=str)


# --- get_event ---


def test_get_event_returns_full_provenance(store):
    event_id, = _seed(store, count=1)
    event = _q(store).get_event(event_id)
    for field in ("event_id", "ts", "kind", "source", "origin", "trust",
                  "ts_ingested", "content_hash", "signature_status",
                  "collector_version", "alert_ids", "incident_ids", "raw_retained"):
        assert field in event, field


def test_get_event_says_the_original_payload_was_not_retained(store):
    """Shield không lưu payload gốc. Nói ra bằng dữ liệu, để giao diện không
    phải đoán và để không ai dựng lại một "raw" giả từ trường đã chuẩn hoá."""
    event_id, = _seed(store, count=1)
    assert _q(store).get_event(event_id)["raw_retained"] is False
    rows = evidence_detail_rows(_q(store).get_event(event_id), lambda k: k, str)
    assert ("evidence.raw_not_retained", "", "raw") in rows


def test_get_event_on_a_missing_id_returns_none(store):
    assert _q(store).get_event("khong-ton-tai") is None


def test_get_event_refuses_an_empty_id(store):
    with pytest.raises(ValueError):
        _q(store).get_event("")


# --- incident -> alert -> evidence -> event ---


def test_the_full_drill_down_works_without_ai(store):
    from shield.security import trust

    event = Event(time.time(), "kernel", "process_exec",
                  {"pid": 4242, "exe": "/tmp/x"}, event_id=new_event_id())
    store.insert_event(event)
    alert = store.insert_alert(trust.stamp_alert(
        __import__("shield.common.models", fromlist=["Alert"]).Alert(
            event.ts, "R1", "warning", "t", "d", "192.0.2.9"), event))
    incident = store.open_or_update_incident(
        correlation_id="C", subject="192.0.2.9", title="t", severity="warning",
        contributing=[{"rule_id": "R1", "ts": event.ts, "severity": "warning",
                       "detail": "d", "alert_id": alert.alert_id,
                       "event_id": event.event_id}],
        evidence_refs=[event.event_id])

    queries = _q(store)
    # incident -> event
    by_incident = queries.search_events(start_time=event.ts - 60, end_time=event.ts + 60,
                                        incident_id=incident["incident_id"])
    assert [e["event_id"] for e in by_incident["events"]] == [event.event_id]
    # alert -> event
    by_alert = queries.search_events(start_time=event.ts - 60, end_time=event.ts + 60,
                                     alert_id=alert.alert_id)
    assert [e["event_id"] for e in by_alert["events"]] == [event.event_id]
    # event -> alert/incident ngược lại
    detail = queries.get_event(event.event_id)
    assert detail["alert_ids"] == [alert.alert_id]
    assert detail["incident_ids"] == [incident["incident_id"]]


def test_an_incident_with_no_evidence_returns_nothing_not_everything(store):
    """Fail closed: không có tham chiếu nào thì trả RỖNG, không phải trả tất cả."""
    _seed(store, count=5)
    result = _q(store).search_events(start_time=999_000, end_time=1_001_000,
                                     incident_id="khong-ton-tai")
    assert result["events"] == []


# --- không phụ thuộc AI ---


def test_everything_still_works_with_the_ai_kill_switch_on(store, monkeypatch):
    from shield.ai.capability import KILL_SWITCH_ENV

    event_id, = _seed(store, count=1)
    baseline = _q(store).search_events(start_time=999_000, end_time=1_001_000)
    monkeypatch.setenv(KILL_SWITCH_ENV, "1")
    assert _q(store).search_events(start_time=999_000, end_time=1_001_000) == baseline
    assert _q(store).get_event(event_id) is not None


def test_the_expert_read_path_never_touches_the_ai_package():
    for relative in ("shield/evidence/queries.py", "shield/ui/evidence_view.py"):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = (node.module or "") if isinstance(node, ast.ImportFrom) else (
                ",".join(a.name for a in node.names) if isinstance(node, ast.Import) else "")
            assert "shield.ai" not in module, f"{relative}: {module}"


# --- giao diện: không có đường đọc thứ hai ---


def test_the_ui_never_writes_sql():
    source = (ROOT / "shield" / "ui" / "__main__.py").read_text(encoding="utf-8")
    for statement in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", ".execute("):
        assert statement not in source, f"giao diện tự chạy SQL: {statement!r}"


def test_the_evidence_tab_reads_only_through_ipc():
    source = (ROOT / "shield" / "ui" / "__main__.py").read_text(encoding="utf-8")
    start = source.index("class EvidenceTab")
    body = source[start:source.index("class ResponseTab")]
    assert '"cmd": "expert_search_events"' in body
    assert '"cmd": "expert_get_event"' in body
    assert "self.store" not in body, "tab bằng chứng tự mở database"


def test_no_second_query_layer_was_created():
    """Mở rộng `EvidenceQueries`, không dựng `ExpertQueries`. Một lớp đọc thứ
    hai nghĩa là dựng lại trần, timeout, che bí mật và nhật ký — rồi để chúng
    lệch nhau."""
    names = []
    for path in sorted(ROOT.glob("shield/**/*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names += [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    assert "ExpertQueries" not in names
    assert sum(1 for n in names if n == "EvidenceQueries") == 1


# --- người xem có trần ---


def test_the_live_feed_never_blocks_the_event_path():
    """`IpcServer.broadcast` gọi `await w.drain()`. Nếu nó nằm trên vòng tiêu
    thụ event thì một giao diện đọc chậm sẽ làm nghẽn việc thu thập."""
    import asyncio

    from shield.agent.__main__ import LiveEvidenceFeed

    async def scenario():
        feed = LiveEvidenceFeed(maxsize=3)
        for index in range(10):
            feed.offer(index)          # đồng bộ, không await
        assert feed.queue.qsize() == 3
        assert feed.dropped == 7
        return True

    assert asyncio.run(scenario())


def test_offering_to_a_full_feed_is_synchronous_and_total():
    import ast as _ast

    tree = _ast.parse((ROOT / "shield" / "agent" / "__main__.py").read_text(encoding="utf-8"))
    offer = next(n for n in _ast.walk(tree)
                 if isinstance(n, _ast.FunctionDef) and n.name == "offer")
    assert not any(isinstance(n, _ast.Await) for n in _ast.walk(offer)), \
        "offer() chờ — nó nằm trên đường event và không được phép chờ"


def test_the_live_feed_redacts_before_broadcasting():
    source = (ROOT / "shield" / "agent" / "__main__.py").read_text(encoding="utf-8")
    start = source.index("async def live_evidence_loop")
    body = source[start:source.index("async def run_event_consumer")]
    assert "redact(" in body


# --- dựng màn hình chi tiết ---


def test_the_detail_groups_are_in_a_fixed_order():
    event = {"event_id": "a", "ts": 1.0, "kind": "k", "source": "s", "origin": "o",
             "trust": "authenticated", "data": {"z": 1, "a": 2}, "raw_retained": False}
    groups = [g for _, _, g in evidence_detail_rows(event, lambda k: k, str)]
    assert groups == sorted(groups, key=["identity", "provenance", "normalized",
                                         "links", "raw"].index)


def test_the_normalized_field_order_is_deterministic():
    event = {"event_id": "a", "data": {"z": 1, "m": 2, "a": 3}, "raw_retained": False}
    labels = [k for k, _, g in evidence_detail_rows(event, lambda k: k, str)
              if g == "normalized"]
    assert labels == ["a", "m", "z"]


def test_a_missing_event_says_so_rather_than_rendering_blanks():
    assert evidence_detail_rows(None, lambda k: k, str) == \
        [("evidence.not_found", "", "identity")]


def test_the_summary_is_built_from_data_not_written():
    """Một bản tóm tắt do máy viết ra sẽ được đọc như một kết luận, và màn hình
    này tồn tại để người ta KHÔNG phải tin kết luận nào cả."""
    event = {"data": {"exe": "/usr/bin/curl", "remote_ip": "1.2.3.4", "pid": 9}}
    summary = event_summary(event)
    assert "exe=/usr/bin/curl" in summary and "remote_ip=1.2.3.4" in summary
    assert event_subject(event) == "1.2.3.4"
    assert event_summary({"data": {}}) == "—"


def test_every_label_key_exists_in_both_languages():
    from shield.ui.i18n import STRINGS

    event = {"event_id": "a", "ts": 1.0, "kind": "k", "source": "s",
             "data": {"pid": 1}, "raw_retained": False}
    keys = {k for k, _, _ in evidence_detail_rows(event, lambda x: x, str)}
    keys |= {f"evidence.group.{g}" for g in
             ("identity", "provenance", "normalized", "links", "raw")}
    keys |= {"nav.evidence", "evidence.sub", "evidence.viewer_status",
             "evidence.not_found", "evidence.raw_not_retained", "log.pause",
             "log.resume", "log.viewer_status"}
    for key in sorted(keys):
        if key in ("pid",):          # tên trường dữ liệu, KHÔNG dịch
            continue
        assert key in STRINGS, key
        vietnamese, english = STRINGS[key]
        assert vietnamese and english and vietnamese != english, key


# --- kế hoạch truy vấn ---


def test_the_hot_path_queries_use_indexes(store):
    now = time.time()
    plans = [
        ("time+kind", "SELECT id FROM events WHERE ts>=? AND ts<=? AND kind=? "
                      "ORDER BY ts DESC, id DESC LIMIT 100", (now - 60, now, "k")),
        ("time+source", "SELECT id FROM events WHERE ts>=? AND ts<=? AND source=? "
                        "ORDER BY ts DESC, id DESC LIMIT 100", (now - 60, now, "s")),
        ("event_id", "SELECT id FROM events WHERE event_id != '' AND event_id=?", ("x",)),
    ]
    for name, sql, params in plans:
        plan = [row[3] for row in store.conn.execute(
            "EXPLAIN QUERY PLAN " + sql, params).fetchall()]
        assert any("USING" in step and "INDEX" in step for step in plan), f"{name}: {plan}"
        assert not any(step.startswith("SCAN events") and "COVERING" not in step
                       for step in plan), f"{name}: {plan}"


def test_the_source_index_exists(store):
    names = {row[0] for row in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='events'")}
    assert "idx_events_source_ts" in names


def test_nothing_is_encoded_when_no_viewer_is_connected():
    """~11 event mỗi giây × cả ngày là rất nhiều JSON không ai đọc."""
    source = (ROOT / "shield" / "agent" / "__main__.py").read_text(encoding="utf-8")
    body = source[source.index("async def live_evidence_loop"):
                  source.index("async def run_event_consumer")]
    assert "has_clients()" in body
    assert body.index("has_clients()") < body.index("to_dict()")


# --- dữ liệu lịch sử chưa che: bảo vệ ở THỜI ĐIỂM ĐỌC ---
#
# Database production có 1,89 triệu event ghi TRƯỚC khi `cmdline` được che ở
# tầng thu thập (A2, 23/08). Không thể sửa quá khứ, và sửa quá khứ cũng phá
# `content_hash` của mọi bản ghi bị chạm. Nên câu hỏi đúng không phải "database
# có sạch không" mà là "giao diện có thể hiện ra không".

LEGACY_CANARY = "ZZLEGACYCANARY9182736455ZZ"


def _insert_legacy_row(store, payload: dict) -> str:
    """Ghi thẳng vào bảng, KHÔNG qua collector — mô phỏng dòng có từ trước khi
    tầng thu thập biết che."""
    event_id = new_event_id()
    store.conn.execute(
        "INSERT INTO events(ts, source, kind, data, origin, trust, event_id, "
        "ts_ingested, content_hash, signature_status, collector_version) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (1_000_500.0, "endpoint", "process_started", json.dumps(payload),
         "local", "authenticated", event_id, 1_000_500.0, "", "unsigned", ""))
    store.conn.commit()
    return event_id


@pytest.mark.parametrize("payload", [
    {"cmdline": f"/usr/bin/curl --header API_KEY={LEGACY_CANARY}"},
    {"cmdline": f"/usr/bin/x --auth=Bearer {LEGACY_CANARY}aaaaaaaaaaaaaaaa"},
    {"token": LEGACY_CANARY},
    {"nested": {"password": LEGACY_CANARY}},
    {"cmdline": f"ghp_{LEGACY_CANARY}bbbbbbbbbbbbbbbbbbbb"},
    {"note": f"-----BEGIN RSA PRIVATE KEY-----\n{LEGACY_CANARY}"},
])
def test_a_legacy_plaintext_row_never_reaches_the_expert_response(store, payload):
    event_id = _insert_legacy_row(store, payload)
    # Dòng thô TRONG database đúng là còn nguyên văn — đó là tiền đề của bài test.
    stored = store.conn.execute(
        "SELECT data FROM events WHERE event_id != '' AND event_id=?", (event_id,)
    ).fetchone()[0]
    assert LEGACY_CANARY in stored, "bài test này không chứng minh gì nếu dòng đã sạch sẵn"

    queries = _q(store)
    found = queries.search_events(start_time=999_000, end_time=1_001_000)
    assert LEGACY_CANARY not in json.dumps(found, default=str), "lọt qua search_events"
    detail = queries.get_event(event_id)
    assert LEGACY_CANARY not in json.dumps(detail, default=str), "lọt qua get_event"
    assert LEGACY_CANARY not in json.dumps(queries.audit.entries, default=str), \
        "lọt vào nhật ký truy vấn"


def test_a_legacy_plaintext_row_never_reaches_the_live_stream():
    """Đường trực tiếp đi qua `live_evidence_loop`, không qua `EvidenceQueries`
    — nên nó phải che RIÊNG, và có test riêng."""
    from shield.common.secrets import redact

    payload = {"cmdline": f"/usr/bin/curl --header API_KEY={LEGACY_CANARY}",
               "token": LEGACY_CANARY}
    assert LEGACY_CANARY not in json.dumps(redact(payload))

    source = (ROOT / "shield" / "agent" / "__main__.py").read_text(encoding="utf-8")
    body = source[source.index("async def live_evidence_loop"):
                  source.index("async def run_event_consumer")]
    assert 'payload["data"] = redact(' in body, \
        "đường trực tiếp không che — nó KHÔNG đi qua EvidenceQueries"
    assert body.index("redact(") < body.index("broadcast("), "che SAU khi đã gửi"


def test_the_ui_renders_only_what_the_read_path_returned():
    """Giao diện không có đường nào lấy dữ liệu ngoài hai lệnh IPC, nên nó
    không thể hiện ra thứ mà tầng đọc đã che."""
    source = (ROOT / "shield" / "ui" / "__main__.py").read_text(encoding="utf-8")
    body = source[source.index("class EvidenceTab"):source.index("class ResponseTab")]
    assert "sqlite3" not in body and "self.store" not in body
    assert "open(" not in body


def test_a_connect_with_an_executable_shows_it_without_any_prose():
    """`exe` phải nổi lên như dữ liệu chuẩn hoá, không kèm câu diễn giải nào.

    Màn hình này tồn tại để người điều tra KHÔNG phải tin một kết luận nào —
    nên đường dẫn hiện ra đúng như đọc được, kể cả hậu tố `(deleted)`.
    """
    from shield.ui.evidence_view import evidence_detail_rows, event_summary

    event = {"event_id": "a" * 32, "ts": 1.0, "kind": "socket_connect",
             "data": {"comm": "curl", "exe": "/tmp/x (deleted)",
                      "remote_ip": "::1", "remote_port": 443}}
    rows = evidence_detail_rows(event, lambda k: k, lambda t: str(t))
    chuan_hoa = {k: v for k, v, nhom in rows if nhom == "normalized"}
    assert chuan_hoa["exe"] == "/tmp/x (deleted)"
    assert event_summary(event).startswith("exe=/tmp/x (deleted)")
