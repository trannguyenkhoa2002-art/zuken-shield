"""Phase 1: incident phải nói được VÌ SAO nó là một sự việc.

Trước v10, `incidents` gộp alert theo `correlation_id` mà không lưu lại điều gì
đã tạo ra quyết định gộp. Tiêu chí "every incident claim can trace back to
evidence" vì thế không kiểm được — và ở 3.0 thì model sẽ phải ĐOÁN lý do gộp,
đúng thứ mà mục 16/17 của kế hoạch cấm.

v10 cộng thêm ba thứ, không xoá thứ nào:

- `incident_alerts.alert_id` -> `alerts.id`, tham chiếu chính danh;
- `incident_correlation_reasons`, lý do gộp dạng dữ liệu, không phải câu chữ;
- `incident_refs`, liên kết sang `events.event_id` và `graph_entities.entity_id`.

`response_jobs` KHÔNG có bảng liên kết: cột `response_jobs.incident_id` đã tồn
tại từ 2.0 và được đọc thẳng.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from pathlib import Path

import pytest

from shield.agent.store import SCHEMA_VERSION, Store
from shield.common.models import Alert
from shield.security.correlation import CorrelationEngine, CorrelationRule

ROOT = Path(__file__).resolve().parent.parent


def _engine() -> CorrelationEngine:
    return CorrelationEngine([
        CorrelationRule(
            id="C_COMBO", required_rules=frozenset({"R1", "R2"}), window_s=600,
            title="combo", mitre_techniques=("T1046",), recommended_action="snapshot_state"),
        CorrelationRule(
            id="C_BURST", required_rules=frozenset({"R3"}), window_s=600,
            title="burst", min_count=3),
    ])


def _alert(rule_id: str, ts: float, alert_id: int = 0, subject: str = "192.0.2.9") -> Alert:
    return Alert(ts, rule_id, "warning", "t", "d", subject, alert_id=alert_id)


# --- lý do gộp là dữ liệu, không phải văn xuôi ---


def test_the_reason_carries_only_rule_inputs_and_measurements():
    """Không trường nào ở đây là câu chữ. Nếu có, nó sẽ là chỗ duy nhất người
    ta nhét lời giải thích vào — và lúc đó 'structured' chỉ còn là tên gọi."""
    engine = _engine()
    engine.correlate(_alert("R1", 1000.0))
    correlations = engine.correlate(_alert("R2", 1010.0))
    assert len(correlations) == 1
    reason = correlations[0].reason
    assert reason == {
        "reason_kind": "rule_combination",
        "rule_id": "C_COMBO",
        "subject": "192.0.2.9",
        "window_s": 600.0,
        "required_rules": ["R1", "R2"],
        "observed_rules": ["R1", "R2"],
        "min_count": 0,
        "observed_count": 2,
        "first_contributing_ts": 1000.0,
        "last_contributing_ts": 1010.0,
    }


def test_a_threshold_rule_is_a_different_reason_kind():
    engine = _engine()
    for index in range(3):
        correlations = engine.correlate(_alert("R3", 2000.0 + index))
    reason = correlations[0].reason
    assert reason["reason_kind"] == "threshold_count"
    assert reason["min_count"] == 3 and reason["observed_count"] == 3
    assert reason["required_rules"] == ["R3"]


def test_the_same_input_gives_the_same_reason():
    """Tiêu chí chấp nhận: 'Incident creation is deterministic for the same
    input dataset.' Hai engine độc lập, cùng chuỗi alert, phải cho dấu bằng."""
    def run():
        engine = _engine()
        engine.correlate(_alert("R1", 1000.0, alert_id=11))
        return engine.correlate(_alert("R2", 1010.0, alert_id=12))[0]

    first, second = run(), run()
    assert first.reason == second.reason
    assert first.contributing == second.contributing


def test_every_reason_traces_back_to_a_loaded_rule():
    """Lý do phải trỏ về một luật CÓ THẬT trong pack đã ký, không phải một id
    được dựng ra lúc chạy."""
    rules = CorrelationRule.load_all(ROOT / "shield" / "rules" / "correlation.json")
    known = {rule.id for rule in rules}
    engine = CorrelationEngine(rules)
    seen = []
    for rule in rules:
        for index, rule_id in enumerate(sorted(rule.required_rules)):
            count = max(rule.min_count, len(rule.required_rules))
            for repeat in range(count):
                for correlation in engine.correlate(
                        _alert(rule_id, 5000.0 + index * 10 + repeat, subject="s")):
                    seen.append(correlation.reason)
    assert seen, "không luật nào khớp — bài test này sẽ không chứng minh được gì"
    for reason in seen:
        assert reason["rule_id"] in known
        assert set(reason["observed_rules"]) <= set(reason["required_rules"])


# --- tham chiếu chính danh, không có hệ định danh thứ hai ---


def test_insert_alert_returns_the_canonical_alerts_row_id(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    stored = store.insert_alert(_alert("R1", 1000.0))
    assert stored.alert_id > 0
    row = store.conn.execute(
        "SELECT rule_id FROM alerts WHERE id=?", (stored.alert_id,)).fetchone()
    assert row[0] == "R1"


def test_dedupe_returns_the_id_of_the_row_it_merged_into(tmp_path):
    """Đây là lý do tồn tại của `alert_id`. Gộp trùng CẬP NHẬT `alerts.ts`, nên
    tra ngược theo (rule_id, ts) trỏ vào một thời điểm không còn tồn tại."""
    store = Store(tmp_path / "s.db", allow_migration=True)
    first = store.insert_alert(_alert("R1", 1000.0))
    second = store.insert_alert(_alert("R1", 1100.0))
    assert second.alert_id == first.alert_id
    stored_ts = store.conn.execute(
        "SELECT ts FROM alerts WHERE id=?", (first.alert_id,)).fetchone()[0]
    assert stored_ts == 1100.0
    assert store.conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE ts=?", (1000.0,)).fetchone()[0] == 0


def test_contributing_alerts_are_linked_by_alert_id(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    engine = _engine()
    stored = [store.insert_alert(_alert("R1", 1000.0)),
              store.insert_alert(_alert("R2", 1010.0))]
    for alert in stored:
        correlations = engine.correlate(alert)
    incident = store.open_or_update_incident(
        correlation_id="C_COMBO", subject="192.0.2.9", title="t", severity="critical",
        contributing=correlations[0].contributing, reason=correlations[0].reason)
    assert store.incident_alert_ids(incident["incident_id"]) == \
        sorted(alert.alert_id for alert in stored)


def test_an_alert_in_two_incidents_is_visible_not_silent(tmp_path):
    """Tiêu chí chấp nhận: 'Same event cannot silently appear in conflicting
    incidents without explicit relationship.' Không cấm — một alert THUỘC về
    nhiều sự việc là chuyện có thật. Điều bị cấm là không tra ra được."""
    store = Store(tmp_path / "s.db", allow_migration=True)
    stored = store.insert_alert(_alert("R1", 1000.0))
    contributing = [{"rule_id": "R1", "ts": 1000.0, "severity": "warning",
                     "detail": "d", "alert_id": stored.alert_id}]
    first = store.open_or_update_incident(
        correlation_id="C_A", subject="192.0.2.9", title="a", severity="warning",
        contributing=contributing)
    second = store.open_or_update_incident(
        correlation_id="C_B", subject="192.0.2.9", title="b", severity="critical",
        contributing=contributing)
    assert first["incident_id"] != second["incident_id"]
    assert store.incidents_for_alert(stored.alert_id) == \
        sorted([first["incident_id"], second["incident_id"]])


def test_an_unstored_alert_has_no_incident_relationship(tmp_path):
    """alert_id 0 nghĩa là 'chưa lưu'. Không bao giờ được dùng làm khoá tra —
    nếu dùng, mọi alert chưa lưu sẽ trông như thuộc cùng một sự việc."""
    store = Store(tmp_path / "s.db", allow_migration=True)
    store.open_or_update_incident(
        correlation_id="C", subject="s", title="t", severity="warning",
        contributing=[{"rule_id": "R1", "ts": 1.0, "severity": "info",
                       "detail": "", "alert_id": 0}])
    assert store.incidents_for_alert(0) == []


def test_a_dangling_evidence_ref_is_rejected(tmp_path):
    """Fail closed. Một incident trỏ tới bằng chứng không tồn tại còn tệ hơn
    một incident không có tham chiếu nào: cái sau nhìn ra được là thiếu."""
    store = Store(tmp_path / "s.db", allow_migration=True)
    with pytest.raises(ValueError, match="treo"):
        store.open_or_update_incident(
            correlation_id="C", subject="s", title="t", severity="warning",
            evidence_refs=["ev-khong-ton-tai"])


def test_a_dangling_asset_ref_is_rejected(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    with pytest.raises(ValueError, match="treo"):
        store.open_or_update_incident(
            correlation_id="C", subject="s", title="t", severity="warning",
            asset_refs=["entity-khong-ton-tai"])


def test_a_real_evidence_ref_is_accepted_and_read_back(tmp_path):
    from shield.common.models import Event, new_event_id

    store = Store(tmp_path / "s.db", allow_migration=True)
    event = Event(time.time(), "test", "process_exec", {"pid": 1},
                  event_id=new_event_id())
    store.insert_event(event)
    incident = store.open_or_update_incident(
        correlation_id="C", subject="s", title="t", severity="warning",
        evidence_refs=[event.event_id])
    assert store.incident_refs(incident["incident_id"], "evidence") == \
        [{"ref_kind": "evidence", "ref_id": event.event_id}]


def test_an_unknown_reason_field_is_rejected(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    with pytest.raises(ValueError, match="trường lạ"):
        store.open_or_update_incident(
            correlation_id="C", subject="s", title="t", severity="warning",
            reason={"reason_kind": "rule_combination", "rule_id": "C",
                    "explanation": "vì tôi nghĩ vậy"})


def test_a_reason_without_a_rule_is_rejected(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    with pytest.raises(ValueError, match="trỏ về rule"):
        store.open_or_update_incident(
            correlation_id="C", subject="s", title="t", severity="warning",
            reason={"reason_kind": "rule_combination", "rule_id": ""})


def test_response_jobs_are_read_from_the_existing_column_not_a_copy(tmp_path):
    """Không có bảng liên kết response_job. Nếu có ai thêm một cái, test này
    vẫn xanh — nhưng `incident_refs` sẽ từ chối kind đó, xem dưới."""
    from shield.response.jobs import ResponseJobStore

    store = Store(tmp_path / "s.db", allow_migration=True)
    incident = store.open_or_update_incident(
        correlation_id="C", subject="s", title="t", severity="warning")
    jobs = ResponseJobStore(store.conn)
    job, created = jobs.create(idempotency_key="k1", action="block_ip",
                               target={"ip": "192.0.2.1"},
                               incident_id=incident["incident_id"])
    assert created
    assert store.incident_response_jobs(incident["incident_id"]) == [job.job_id]


def test_every_new_incident_lookup_uses_an_index(tmp_path):
    """Một truy vấn quét toàn bảng ở đường nóng đã từng đốt trọn một nhân CPU
    và làm cả máy chậm 10 lần. Kiểm KẾ HOẠCH truy vấn, không phải kết quả: một
    bài test chỉ so kết quả thì xanh dù có index hay không."""
    store = Store(tmp_path / "s.db", allow_migration=True)
    queries = [
        ("SELECT entity_id FROM graph_entities WHERE canonical_key=? LIMIT 20", ("k",)),
        ("SELECT job_id FROM response_jobs WHERE incident_id=?", ("i",)),
        ("SELECT DISTINCT alert_id FROM incident_alerts WHERE incident_id=? AND alert_id>0",
         ("i",)),
        ("SELECT ref_kind,ref_id FROM incident_refs WHERE incident_id=?", ("i",)),
        ("SELECT reason_kind FROM incident_correlation_reasons WHERE incident_id=?", ("i",)),
    ]
    for sql, params in queries:
        plan = [row[3] for row in
                store.conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()]
        assert any("USING" in step and "INDEX" in step for step in plan), \
            f"quét toàn bảng: {sql}\n{plan}"
        assert not any(step.startswith("SCAN") and "COVERING" not in step
                       for step in plan), f"SCAN ở: {sql}\n{plan}"


def test_incident_refs_refuses_a_kind_it_has_no_source_table_for(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    with pytest.raises(ValueError, match="không hợp lệ"):
        store.incident_refs("x", "response_job")


def test_open_or_update_incident_is_the_only_incident_write_path():
    """Một đường ghi, không hai. Nếu danh sách này dài ra thì có ai đó vừa mở
    một đường ghi incident bỏ qua kiểm tra tham chiếu và lý do gộp."""
    import re

    allowed = {
        # đường ghi chính danh + đổi trạng thái + migration
        "shield/agent/store.py",
    }
    pattern = re.compile(
        r"(INSERT\s+(OR\s+\w+\s+)?INTO|UPDATE|DELETE\s+FROM)\s+"
        r"(incidents|incident_alerts|incident_refs|incident_correlation_reasons)\b",
        re.IGNORECASE)
    offenders = []
    for path in sorted(ROOT.glob("shield/**/*.py")):
        relative = str(path.relative_to(ROOT))
        if relative in allowed:
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(relative)
    assert offenders == [], f"đường ghi incident thứ hai ở: {offenders}"


def test_only_the_alert_consumer_opens_incidents():
    import ast

    callers = []
    for path in sorted(ROOT.glob("shield/**/*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "open_or_update_incident"):
                callers.append(str(path.relative_to(ROOT)))
    assert sorted(set(callers)) == ["shield/agent/__main__.py"], callers


# --- lan truyền bằng chứng: event_id -> alert -> incident ---


def _event(kind: str = "process_exec", ts: float = 1000.0):
    from shield.common.models import Event

    return Event(ts, "test", kind, {"pid": 4242, "exe": "/tmp/x"})


def test_an_alert_keeps_the_event_id_of_the_event_that_created_it():
    from shield.security import trust

    event = _event()
    assert event.event_id, "Event tự sinh event_id — giả định của cả chuỗi này"
    stamped = trust.stamp_alert(_alert("R1", 1000.0), event)
    assert stamped.evidence["event_id"] == event.event_id


def test_stamping_does_not_invent_an_id_when_the_event_has_none():
    """Yêu cầu 4: không suy đoán. Một alert không truy được về event nào phải
    NHÌN RA ĐƯỢC là như vậy — gắn chuỗi rỗng làm nó trông như có nguồn."""
    from shield.common.models import Event
    from shield.security import trust

    event = Event(1000.0, "test", "k", {}, event_id="")
    object.__setattr__(event, "event_id", "")
    stamped = trust.stamp_alert(_alert("R1", 1000.0), event)
    assert "event_id" not in stamped.evidence


def test_a_detector_that_knows_better_keeps_its_own_reference():
    from shield.security import trust

    event = _event()
    alert = Alert(1000.0, "R1", "warning", "t", "d", "s",
                  evidence={"event_id": "ev-do-detector-chon"})
    assert trust.stamp_alert(alert, event).evidence["event_id"] == "ev-do-detector-chon"


def test_an_incident_links_to_the_event_id_of_its_contributing_alerts(tmp_path):
    from shield.security import trust

    store = Store(tmp_path / "s.db", allow_migration=True)
    engine = _engine()
    events, stored = [], []
    for index, rule_id in enumerate(("R1", "R2")):
        event = _event(ts=1000.0 + index)
        store.insert_event(event)
        events.append(event)
        alert = trust.stamp_alert(_alert(rule_id, 1000.0 + index), event)
        stored.append(store.insert_alert(alert))
    for alert in stored:
        correlations = engine.correlate(alert)

    refs = store.existing_event_ids(
        item["event_id"] for item in correlations[0].contributing)
    incident = store.open_or_update_incident(
        correlation_id="C_COMBO", subject="192.0.2.9", title="t", severity="critical",
        contributing=correlations[0].contributing, reason=correlations[0].reason,
        evidence_refs=refs)

    linked = [row["ref_id"] for row in
              store.incident_refs(incident["incident_id"], "evidence")]
    assert linked == sorted(event.event_id for event in events)


def test_incident_to_evidence_to_raw_event_can_be_traversed(tmp_path):
    """Incident -> Finding -> Evidence -> Raw record, đúng bốn bước của mục 10
    kế hoạch. Mỗi bước là một khoá chính đã có, không có bảng tra nào ở giữa."""
    from shield.security import trust

    store = Store(tmp_path / "s.db", allow_migration=True)
    event = _event()
    store.insert_event(event)
    alert = store.insert_alert(trust.stamp_alert(_alert("R1", 1000.0), event))
    incident = store.open_or_update_incident(
        correlation_id="C", subject="192.0.2.9", title="t", severity="warning",
        contributing=[{"rule_id": "R1", "ts": 1000.0, "severity": "warning",
                       "detail": "d", "alert_id": alert.alert_id,
                       "event_id": event.event_id}],
        evidence_refs=[event.event_id])

    # incident -> alert
    assert store.incident_alert_ids(incident["incident_id"]) == [alert.alert_id]
    # incident -> evidence ref
    refs = [row["ref_id"] for row in
            store.incident_refs(incident["incident_id"], "evidence")]
    assert refs == [event.event_id]
    # evidence ref -> bản ghi thô + đã chuẩn hoá
    raw = store.conn.execute(
        "SELECT source, kind, data, origin, trust FROM events WHERE event_id=?",
        (refs[0],)).fetchone()
    assert raw is not None
    assert raw[1] == "process_exec"
    assert json.loads(raw[2])["pid"] == 4242


def test_the_same_input_yields_the_same_evidence_refs(tmp_path):
    from shield.security import trust

    def run(path):
        store = Store(path, allow_migration=True)
        engine = _engine()
        for index, rule_id in enumerate(("R1", "R2")):
            event = _event(ts=1000.0 + index)
            object.__setattr__(event, "event_id", f"ev-co-dinh-{index}")
            store.insert_event(event)
            correlations = engine.correlate(
                store.insert_alert(trust.stamp_alert(_alert(rule_id, 1000.0 + index), event)))
        return store.existing_event_ids(
            item["event_id"] for item in correlations[0].contributing)

    assert run(tmp_path / "a.db") == run(tmp_path / "b.db") ==         ["ev-co-dinh-0", "ev-co-dinh-1"]


def test_a_pruned_event_is_dropped_by_the_filter_not_by_an_exception(tmp_path):
    """Chính sách lưu trữ xoá event cũ trong lúc incident mở ra muộn hơn. Nếu
    để lỗi bay lên thì một cơ chế dọn dẹp bình thường sẽ làm sập đường alert."""
    store = Store(tmp_path / "s.db", allow_migration=True)
    event = _event()
    store.insert_event(event)
    assert store.existing_event_ids([event.event_id, "ev-da-bi-don"]) == [event.event_id]


def test_the_ai_kill_switch_does_not_change_evidence_linking(tmp_path, monkeypatch):
    from shield.ai.capability import KILL_SWITCH_ENV
    from shield.security import trust

    def run(path):
        store = Store(path, allow_migration=True)
        event = _event()
        object.__setattr__(event, "event_id", "ev-co-dinh")
        store.insert_event(event)
        alert = store.insert_alert(trust.stamp_alert(_alert("R1", 1000.0), event))
        incident = store.open_or_update_incident(
            correlation_id="C", subject="192.0.2.9", title="t", severity="warning",
            contributing=[{"rule_id": "R1", "ts": 1000.0, "severity": "warning",
                           "detail": "d", "alert_id": alert.alert_id,
                           "event_id": event.event_id}],
            evidence_refs=store.existing_event_ids([alert.evidence["event_id"]]))
        return store.incident_refs(incident["incident_id"])

    baseline = run(tmp_path / "a.db")
    monkeypatch.setenv(KILL_SWITCH_ENV, "1")
    assert run(tmp_path / "b.db") == baseline
    assert baseline == [{"ref_kind": "evidence", "ref_id": "ev-co-dinh"}]


def test_no_detector_writes_an_event_id_itself():
    """Gắn ở MỘT chỗ (`trust.stamp_alert`). Tám detector là tám lần có cơ hội
    quên, hoặc tám cách hiểu khác nhau về 'event nào đã sinh ra alert này'."""
    offenders = []
    for path in sorted(ROOT.glob("shield/agent/detectors/*.py")):
        if '"event_id"' in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"detector tự gắn event_id: {offenders}"


def test_shield_self_observation_alerts_carry_no_evidence_ref():
    """Alert về chính Shield (sức khoẻ, tamper, clock) KHÔNG sinh ra từ một
    event nào. Chúng phải không có `event_id` — chứ không phải có một cái
    trông hợp lệ."""
    from shield.agent.problems import Problem, problem_to_alert

    alert = problem_to_alert(Problem(
        problem_id="collector_silent", severity="warning", title="t", detail="d",
        remedy="r"))
    assert "event_id" not in alert.evidence


# --- AI không tham gia vào correlation ---


def test_correlation_does_not_import_the_ai_package():
    import ast

    for relative in ("shield/security/correlation.py",):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = ""
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
            elif isinstance(node, ast.Import):
                module = ",".join(alias.name for alias in node.names)
            assert "shield.ai" not in module, f"{relative} nhập {module}"


def test_correlation_and_incidents_work_with_the_ai_kill_switch_on(tmp_path, monkeypatch):
    """Tiêu chí chấp nhận: 'Correlation does not require AI.' Bật công tắc tắt
    AI rồi chạy lại phải cho ra ĐÚNG cùng một lý do."""
    from shield.ai.capability import KILL_SWITCH_ENV

    def run():
        engine = _engine()
        engine.correlate(_alert("R1", 1000.0))
        return engine.correlate(_alert("R2", 1010.0))[0].reason

    baseline = run()
    monkeypatch.setenv(KILL_SWITCH_ENV, "1")
    assert run() == baseline


# --- truy vấn incident cũ vẫn tương thích ---


def test_the_existing_incident_queries_are_unchanged(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    incident = store.open_or_update_incident(
        correlation_id="C", subject="192.0.2.9", title="t", severity="critical",
        risk_score=70, mitre_techniques=["T1046"], recommended_action="snapshot_state",
        contributing=[{"rule_id": "R1", "ts": 1000.0, "severity": "warning",
                       "detail": "d", "alert_id": 0}])
    listed = store.list_incidents()
    assert len(listed) == 1
    row = listed[0]
    for key in ("incident_id", "correlation_id", "subject", "title", "severity",
                "risk_score", "state"):
        assert key in row
    assert row["incident_id"] == incident["incident_id"]
    assert store.incident_subjects(incident["incident_id"])
    assert store.set_incident_state(incident["incident_id"], "investigating")


def test_a_caller_that_never_heard_of_v10_still_works(tmp_path):
    """Chữ ký cũ: không `reason`, không ref. Phải chạy y như trước."""
    store = Store(tmp_path / "s.db", allow_migration=True)
    result = store.open_or_update_incident(
        correlation_id="C", subject="s", title="t", severity="warning")
    assert result["incident_id"]
    assert store.incident_correlation_reasons(result["incident_id"]) == []
    assert store.incident_refs(result["incident_id"]) == []


# --- migration v9 -> v10 ---


def _make_v9(path: Path) -> None:
    """Dựng lại hình dạng v9: bỏ hai bảng mới và cột mới, hạ user_version."""
    store = Store(path, allow_migration=True)
    store.conn.execute("DROP TABLE incident_correlation_reasons")
    store.conn.execute("DROP TABLE incident_refs")
    store.conn.execute("DROP INDEX IF EXISTS idx_incident_alerts_alert")
    store.conn.execute("ALTER TABLE incident_alerts DROP COLUMN alert_id")
    store.conn.execute("PRAGMA user_version=9")
    store.conn.execute(
        "INSERT INTO incidents(incident_id,correlation_id,subject,title,severity,"
        "risk_score,confidence,evidence_strength,state,mitre_techniques,"
        "recommended_action,alert_count,first_seen,last_seen) "
        "VALUES('old','C','s','t','warning',10,0.5,0.5,'open','[]','',1,100.0,200.0)")
    store.conn.execute(
        "INSERT INTO incident_alerts(incident_id,rule_id,alert_ts,severity,detail) "
        "VALUES('old','R1',100.0,'warning','d')")
    store.conn.commit()
    store.close()


def test_migration_from_v9_is_additive_and_loses_nothing(tmp_path):
    path = tmp_path / "v9.db"
    _make_v9(path)

    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 9
    before = {t: raw.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("incidents", "incident_alerts", "alerts", "events")}
    columns_before = [r[1] for r in raw.execute("PRAGMA table_info(incidents)")]
    raw.close()

    store = Store(path, allow_migration=True)
    assert store.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    after = {t: store.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
             for t in before}
    assert after == before, "migration làm mất dòng"

    columns_after = [r[1] for r in store.conn.execute("PRAGMA table_info(incidents)")]
    assert columns_after[:len(columns_before)] == columns_before, \
        "cột cũ bị đổi thứ tự hoặc bị xoá — đây không còn là migration cộng thêm"

    assert "alert_id" in {r[1] for r in
                          store.conn.execute("PRAGMA table_info(incident_alerts)")}
    # Dòng cũ KHÔNG được suy ngược alert_id: tra theo (rule_id, ts) chính là
    # phỏng đoán mà cột này sinh ra để thay thế.
    assert store.conn.execute(
        "SELECT alert_id FROM incident_alerts WHERE incident_id='old'").fetchone()[0] == 0
    assert store.incident_alert_ids("old") == []
    assert store.list_incidents()[0]["incident_id"] == "old"
    assert store.conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "v9.db"
    _make_v9(path)
    Store(path, allow_migration=True).close()
    store = Store(path, allow_migration=True)
    assert store.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert store.conn.execute(
        "SELECT COUNT(*) FROM incident_alerts").fetchone()[0] == 1


@pytest.mark.skipif(not os.environ.get("SHIELD_REAL_DB_MIGRATION_TEST"),
                    reason="cần một bản sao database v9 thật; đặt "
                           "SHIELD_REAL_DB_MIGRATION_TEST=<đường dẫn>")
def test_migration_against_a_real_v9_database(tmp_path):
    """Đo trên dữ liệu THẬT. Mọi con số đo trên dữ liệu tổng hợp phải được đo
    lại trên dữ liệu thật trước khi tin — bảy lỗi nghiêm trọng của 2.0 đều có
    một bài test tổng hợp màu xanh nằm ngay bên cạnh."""
    import shutil

    source = Path(os.environ["SHIELD_REAL_DB_MIGRATION_TEST"])
    target = tmp_path / "real.db"
    shutil.copy2(source, target)

    raw = sqlite3.connect(target)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 9, "bản sao không phải v9"
    before = {t: raw.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("events", "alerts", "incidents", "incident_alerts",
                        "graph_entities", "devices")}
    raw.close()

    started = time.time()
    store = Store(target, allow_migration=True)
    elapsed = time.time() - started

    after = {t: store.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
             for t in before}
    assert after == before, f"mất dòng: {before} -> {after}"
    assert store.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert store.conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert elapsed < 60, f"migration mất {elapsed:.1f}s trên dữ liệu thật"


# --- giao diện: bảng "vì sao đây là một sự việc" ---
#
# Kiểm hàm dựng bảng chứ không dựng QApplication: máy CI không có libEGL, và
# ba thứ dễ sai nhất (thứ tự dòng, khoá dịch, trạng thái không có dữ liệu) đều
# nằm trong hàm này.


def _rows(reasons, alert_ids=()):
    from shield.ui.incident_view import correlation_reason_rows

    return correlation_reason_rows(list(reasons), list(alert_ids),
                                   lambda key: f"<{key}>", lambda ts: f"T{ts:g}")


def _reason(**over):
    base = {
        "reason_kind": "rule_combination", "rule_id": "C_COMBO", "subject": "s",
        "window_s": 600.0, "required_rules": ["R1", "R2"],
        "observed_rules": ["R1", "R2"], "min_count": 0, "observed_count": 2,
        "first_contributing_ts": 1000.0, "last_contributing_ts": 1010.0,
    }
    base.update(over)
    return base


def test_a_v10_incident_shows_every_structured_field():
    rows = _rows([_reason()], [7, 8])
    assert rows == [
        ("incidents.reason.kind", "<incidents.reason.kind.rule_combination>"),
        ("incidents.reason.rule", "C_COMBO"),
        ("incidents.reason.window", "<incidents.reason.seconds>"),
        ("incidents.reason.required", "R1, R2"),
        ("incidents.reason.observed", "R1, R2"),
        ("incidents.reason.counts", "0 / 2"),
        ("incidents.reason.first", "T1000"),
        ("incidents.reason.last", "T1010"),
        ("incidents.reason.alerts", "7, 8"),
    ]


def test_a_threshold_incident_shows_its_own_match_type():
    rows = dict(_rows([_reason(reason_kind="threshold_count", min_count=3,
                               observed_count=5)], [1]))
    assert rows["incidents.reason.kind"] == "<incidents.reason.kind.threshold_count>"
    assert rows["incidents.reason.counts"] == "3 / 5"


def test_a_legacy_incident_says_the_data_does_not_exist():
    """Yêu cầu 6: trạng thái 'không có' phải TƯỜNG MINH. Suy diễn một lý do
    nghe hợp lý cho một sự việc cũ là thứ không ai kiểm lại được."""
    assert _rows([]) == [("incidents.reason.legacy", "")]


def test_a_migrated_v9_incident_is_still_readable(tmp_path):
    """Sự việc v9 có alert_id=0 và không có lý do. Phải đọc được, và phải nói
    ra là không có dữ liệu — không được vỡ và không được bịa."""
    path = tmp_path / "v9.db"
    _make_v9(path)
    store = Store(path, allow_migration=True)
    assert store.list_incidents()[0]["incident_id"] == "old"
    assert store.incident_correlation_reasons("old") == []
    assert store.incident_alert_ids("old") == []
    assert _rows(store.incident_correlation_reasons("old"),
                 store.incident_alert_ids("old")) == \
        [("incidents.reason.legacy", "")]


def test_a_v10_incident_without_contributing_alert_ids_says_so():
    rows = dict(_rows([_reason()], []))
    assert rows["incidents.reason.alerts"] == "<incidents.reason.no_alert_ids>"


def test_the_row_order_is_deterministic():
    reasons = [_reason(rule_id="A"), _reason(rule_id="B", first_contributing_ts=2000.0)]
    assert _rows(reasons, [3, 1, 2]) == _rows(reasons, [3, 1, 2])
    labels = [key for key, _ in _rows(reasons, [1])]
    assert labels.count("incidents.reason.rule") == 2
    assert labels[-1] == "incidents.reason.alerts", "alert đóng góp luôn ở cuối"


def test_the_store_returns_reasons_in_a_fixed_order(tmp_path):
    store = Store(tmp_path / "s.db", allow_migration=True)
    incident = store.open_or_update_incident(
        correlation_id="C", subject="s", title="t", severity="warning")
    for rule_id, first in (("Z", 3000.0), ("A", 1000.0), ("M", 2000.0)):
        store.open_or_update_incident(
            correlation_id="C", subject="s", title="t", severity="warning",
            reason=_reason(rule_id=rule_id, first_contributing_ts=first))
    reasons = store.incident_correlation_reasons(incident["incident_id"])
    assert [r["rule_id"] for r in reasons] == ["A", "M", "Z"]


def test_every_label_key_exists_in_both_languages():
    from shield.ui.i18n import STRINGS

    keys = {key for key, _ in _rows([_reason()], [1])}
    keys |= {key for key, _ in _rows([])}
    keys |= {"incidents.reasons_title", "incidents.reason.none",
             "incidents.reason.no_alert_ids", "incidents.reason.seconds",
             "incidents.reason.kind.rule_combination",
             "incidents.reason.kind.threshold_count"}
    for key in sorted(keys):
        assert key in STRINGS, key
        vietnamese, english = STRINGS[key]
        assert vietnamese and english, key
        assert vietnamese != english or key.startswith("incidents.reason.rule"), \
            f"{key}: hai ngôn ngữ giống hệt nhau — nhiều khả năng quên dịch"


def test_the_reason_table_never_renders_a_free_text_field():
    """Nếu ai đó thêm một trường văn xuôi vào lý do gộp, nó phải KHÔNG hiện
    ra ở đây. Store đã từ chối trường lạ; đây là lớp thứ hai."""
    rows = _rows([_reason(**{})], [1])
    values = [value for _, value in rows]
    assert not any(len(value) > 80 for value in values), values
    smuggled = _reason()
    smuggled["observed_rules"] = ["R1"]
    assert all(isinstance(value, str) for _, value in _rows([smuggled], [1]))


def test_the_ui_reads_incidents_through_the_existing_store_path():
    """Không có đường dữ liệu incident thứ hai: tab đọc `self.store`, y như
    bảng incident đã có từ 1.1."""
    source = (ROOT / "shield" / "ui" / "__main__.py").read_text(encoding="utf-8")
    assert "self.store.incident_correlation_reasons(" in source
    assert "self.store.incident_alert_ids(" in source


def test_the_incident_view_module_does_not_import_qt_or_ai():
    import ast

    tree = ast.parse((ROOT / "shield" / "ui" / "incident_view.py").read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
        elif isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
    assert not any(name.startswith(("PySide6", "PyQt6", "shield.ai")) for name in imported), imported


def test_every_correlatable_rule_comes_from_a_detector():
    """Vì sao điều này quan trọng cho "mọi khẳng định truy được về bằng chứng":

    Alert do Shield tự quan sát (sức khoẻ, tamper, đồng hồ, tarpit) KHÔNG sinh
    ra từ một event nào, nên chúng không có `event_id` — và đúng ra là không
    nên có. Nếu một luật correlation lại đòi một rule_id thuộc nhóm đó, thì sẽ
    có incident mà một phần đóng góp không truy ngược được, mà nhìn bên ngoài
    thì y hệt các incident khác.

    Test này giữ ranh giới đó: mọi rule_id mà correlation có thể ghép phải do
    một detector phát ra, tức là đi qua `trust.stamp_alert` và mang event_id.
    """
    pack = json.loads(
        (ROOT / "shield" / "rules" / "correlation.json").read_text(encoding="utf-8"))
    required = set()
    for rule in pack["rules"]:
        required |= set(rule["required_rules"])

    emitted = set()
    sources = list((ROOT / "shield" / "agent" / "detectors").glob("*.py"))
    sources += [ROOT / "shield" / "security" / "rules.py",
                ROOT / "shield" / "security" / "anomaly.py"]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        emitted |= set(re.findall(r'"([A-Z][A-Z0-9_]{4,})"', text))
    for pack_file in (ROOT / "shield" / "rules").glob("*.json"):
        raw = json.loads(pack_file.read_text(encoding="utf-8"))
        if raw.get("pack_type") == "correlation":
            continue
        for item in raw.get("rules", []):
            if item.get("id"):
                emitted.add(str(item["id"]))

    orphans = sorted(required - emitted)
    assert orphans == [], (
        "luật correlation đòi rule_id không do detector nào phát ra, nên alert "
        f"đóng góp sẽ không có event_id: {orphans}")


def test_the_evidence_ref_filter_uses_the_partial_index(tmp_path):
    """Index trên `events.event_id` là index MỘT PHẦN (`WHERE event_id != ''`).
    SQLite chỉ dùng được nó khi câu truy vấn CHỨNG MINH được vị từ đó — một
    tham số ràng buộc thì không chứng minh được gì.

    Đo trên database production 1.837.445 dòng: 256,93 ms quét toàn bảng so với
    0,18 ms dùng index. Và `existing_event_ids()` chạy mỗi lần correlation mở
    một incident, tức là trên đường nóng.

    Kiểm KẾ HOẠCH truy vấn chứ không phải kết quả: một bài test chỉ so kết quả
    thì xanh dù có quét toàn bảng hay không. Đây là lần thứ ba cùng một cái bẫy
    xuất hiện trong repo này.
    """
    store = Store(tmp_path / "s.db", allow_migration=True)
    plan = [row[3] for row in store.conn.execute(
        "EXPLAIN QUERY PLAN SELECT event_id FROM events "
        "WHERE event_id != '' AND event_id IN (?,?)", ("a", "b")).fetchall()]
    assert any("idx_events_event_id" in step for step in plan), plan
    assert not any(step.startswith("SCAN events") for step in plan), plan


def test_no_query_looks_up_event_id_without_proving_the_predicate():
    """Bất biến toàn repo: mọi câu chạm `events.event_id` trong mệnh đề WHERE
    phải kèm `event_id != ''`, nếu không nó quét toàn bảng."""
    import re

    offenders = []
    for path in sorted(ROOT.glob("shield/**/*.py")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"WHERE[^\"']*event_id\s*(=\?|IN \()", text):
            window = text[match.start():match.start() + 220]
            if "event_id != ''" not in window and "event_id!=''" not in window:
                offenders.append(f"{path.relative_to(ROOT)}: {window[:70]}")
    assert offenders == [], offenders
