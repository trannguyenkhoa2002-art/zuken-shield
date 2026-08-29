"""Lưu bền lượt điều tra, khẳng định và lời gọi tool (mục 2.3 và mục 7).

Khi lớp AI nói sai một điều quan trọng, câu hỏi khó nhất không phải "nó nói gì"
mà là **"nó đã nhìn thấy gì lúc nó nói câu đó?"** — và lần khởi động lại thường
xảy ra ngay sau sự cố.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.ai.audit import (
    INVESTIGATION_RETENTION_DAYS,
    TRACE_RETENTION_DAYS,
    InvestigationAudit,
)
from shield.ai.contracts import Hypothesis, InvestigationResult
from shield.ai.local_provider import LocalDeterministicAnalyst
from shield.ai.orchestrator import InvestigationOrchestrator
from shield.ai.prompts import build_request
from shield.common.models import Event
from shield.evidence.models import entity_id_for
from shield.evidence.queries import EvidenceQueries
from shield.evidence.resolver import resolve

ROOT = Path(__file__).resolve().parent.parent


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "shield.db", allow_migration=True)


@pytest.fixture()
def audit(store):
    return InvestigationAudit(store.conn)


def ingest(store: Store, event: Event) -> None:
    with store.conn:
        store.conn.execute(
            "INSERT OR IGNORE INTO events(ts,source,kind,data,origin,trust,event_id,"
            "ts_ingested,content_hash,signature_status,collector_version) "
            "VALUES(?,?,?,'{}',?,?,?,?,?,'unsigned','')",
            (event.ts, event.source, event.kind,
             str(event.data.get("origin") or event.origin), str(event.trust),
             event.event_id, event.ts_ingested, event.content_hash_))
        store.graph.ingest(*resolve(event))


def _result(**overrides) -> InvestigationResult:
    defaults = {
        "investigation_id": "inv-1", "incident_id": "inc-1", "summary": "tóm tắt",
        "summary_key": "ai.local.summary", "summary_params": {"breakdown": "x=1"},
        "provider": "local", "model": "deterministic-v1",
        "hypotheses": (Hypothesis("H1", "Một khẳng định", "unconfirmed",
                               ("event:aaa", "event:bbb"),
                               contradicting_evidence_refs=("event:ccc",),
                               missing_evidence_keys=("ai.local.missing_exec",),
                               statement_key="ai.local.h_write_connect",
                               statement_params={"process": "p1"}),),
    }
    defaults.update(overrides)
    return InvestigationResult(**defaults)


# --- schema ---


def test_every_table_the_plan_requires_exists(store):
    """Mục 7 liệt kê 13 bảng. Thiếu một bảng là một mảng dữ liệu không có chỗ."""
    have = {row[0] for row in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"graph_entities", "graph_edges", "evidence_objects", "investigations",
                "investigation_hypotheses", "investigation_claims", "claim_evidence",
                "ai_tool_calls", "model_runs", "response_jobs", "response_transitions",
                "verification_results", "detector_calibration"}
    assert required <= have, sorted(required - have)


# --- ghi và đọc lại ---


def test_an_investigation_survives_a_restart(tmp_path):
    """Giữ trong bộ nhớ nghĩa là agent khởi động lại một lần là mất sạch."""
    path = tmp_path / "shield.db"
    first = Store(path, allow_migration=True)
    InvestigationAudit(first.conn).record(
        _result(), validation={"checked": 1, "downgraded": 0},
        tool_calls=[{"tool": "counts", "arguments": {}, "rows": 1, "ts": 1000.0}])
    first.close()

    second = Store(path, allow_migration=True)
    try:
        record = InvestigationAudit(second.conn).get("inv-1")
        assert record is not None
        assert record["incident_id"] == "inc-1"
        assert record["hypotheses"][0]["id"] == "H1"
        assert InvestigationAudit(second.conn).tool_calls("inv-1")[0]["tool"] == "counts"
    finally:
        second.close()


def test_claims_and_their_evidence_are_stored_separately(audit):
    audit.record(_result(), validation={"checked": 1})
    hypothesis = audit.get("inv-1")["hypotheses"][0]
    assert hypothesis["evidence_refs"] == ["event:aaa", "event:bbb"]
    assert hypothesis["contradicting_evidence_refs"] == ["event:ccc"]
    assert hypothesis["missing_evidence_keys"] == ["ai.local.missing_exec"]


def test_contradicting_evidence_is_stored_beside_supporting(audit):
    """Giấu bằng chứng mâu thuẫn là cách làm một kết luận sai trông vững chắc."""
    audit.record(_result(), validation={"checked": 1})
    rows = audit.conn.execute(
        "SELECT role, COUNT(*) FROM claim_evidence GROUP BY role ORDER BY role").fetchall()
    assert dict(rows) == {"contradicting": 1, "missing": 1, "supporting": 2}


def test_translation_keys_survive_the_round_trip(audit):
    """Một hồ sơ đọc lại sáu tháng sau vẫn phải hiển thị được bằng ngôn ngữ
    người đọc chọn lúc đó."""
    audit.record(_result(), validation={"checked": 1})
    record = audit.get("inv-1")
    assert record["summary_key"] == "ai.local.summary"
    assert record["summary_params"] == {"breakdown": "x=1"}
    assert record["hypotheses"][0]["statement_key"] == "ai.local.h_write_connect"
    assert record["hypotheses"][0]["statement_params"] == {"process": "p1"}


def test_a_downgrade_reason_is_kept(audit):
    """Người đọc phải thấy được rằng máy đã can thiệp, không chỉ thấy kết quả
    sau can thiệp."""
    audit.record(_result(hypotheses=(
        Hypothesis("H1", "s", "insufficient_evidence", ("event:x",),
                   downgrade_reason="evidence không tồn tại"),)),
        validation={"checked": 1, "downgraded": 1})
    assert audit.get("inv-1")["hypotheses"][0]["downgrade_reason"] == "evidence không tồn tại"


def test_the_run_counters_are_stored(audit):
    audit.record(_result(), validation={"checked": 4, "downgraded": 2,
                                        "policy_violations": 1},
                 tool_calls=[{"tool": "counts"}] * 3)
    record = audit.get("inv-1")
    assert (record["claims"], record["downgraded"]) == (4, 2)
    assert record["tool_calls"] == 3 and record["policy_violations"] == 1


def test_errors_are_stored_so_a_failed_run_is_still_a_record(audit):
    """Một lượt hỏng vẫn là một bản ghi: một provider hỏng liên tục là một
    provider cần tắt, và không ai thấy điều đó nếu lượt hỏng không được lưu."""
    audit.record(_result(hypotheses=(), errors=("model hết thời gian",)),
                 validation={})
    assert audit.get("inv-1")["errors"] == ["model hết thời gian"]


def test_a_failed_model_run_is_recorded(audit):
    audit.record_model_run("inv-1", provider="local", model="v1", started_ts=1000.0,
                           elapsed_s=0.5, ok=False, error="nổ")
    row = audit.conn.execute("SELECT ok, error FROM model_runs").fetchone()
    assert row == (0, "nổ")


# --- redaction ---


def test_secrets_never_reach_the_stored_tool_call_log(audit):
    """Bảng này sống lâu hơn nhật ký trong bộ nhớ, nên nó đáng một lần kiểm nữa."""
    audit.record(_result(), validation={},
                 tool_calls=[{"tool": "counts",
                              "arguments": {"note": "ghp_" + "a" * 35,
                                            "password": "hunter2"}}])
    stored = json.dumps(audit.tool_calls("inv-1"), ensure_ascii=False)
    assert "hunter2" not in stored
    assert "ghp_" not in stored


# --- đo trên dữ liệu đã lưu ---


def test_the_unsupported_claim_rate_is_measurable_across_runs(audit):
    """Trước đây con số này chỉ tồn tại trong một lượt chạy. Đo trên dữ liệu đã
    lưu mới trả lời được câu đáng hỏi: lớp phân tích đang tốt lên hay tệ đi?"""
    audit.record(_result(investigation_id="a"), validation={"checked": 10, "downgraded": 1})
    audit.record(_result(investigation_id="b"), validation={"checked": 10, "downgraded": 3})
    assert audit.unsupported_claim_rate() == pytest.approx(0.2)


def test_the_rate_is_none_when_nothing_was_measured(audit):
    assert audit.unsupported_claim_rate() is None


def test_investigations_can_be_listed_per_incident(audit):
    for index in range(3):
        audit.record(_result(investigation_id=f"inv-{index}", incident_id="inc-A"),
                     validation={})
    audit.record(_result(investigation_id="other", incident_id="inc-B"), validation={})
    assert len(audit.for_incident("inc-A")) == 3
    assert len(audit.for_incident("inc-B")) == 1


# --- hai hạn lưu trữ ---


def test_traces_expire_sooner_than_the_record(store):
    """Vết model nhiều và nhanh cũ; hồ sơ điều tra thì không. Một hạn chung sẽ
    hoặc giữ vết quá lâu, hoặc xoá hồ sơ quá sớm."""
    assert TRACE_RETENTION_DAYS < INVESTIGATION_RETENTION_DAYS

    clock = [1_000_000.0]
    audit = InvestigationAudit(store.conn, clock=lambda: clock[0])
    audit.record(_result(), validation={"checked": 1},
                 tool_calls=[{"tool": "counts", "ts": clock[0]}])

    clock[0] += (TRACE_RETENTION_DAYS + 1) * 86400
    removed = audit.prune()
    assert removed["traces_removed"] >= 1
    assert removed["investigations_removed"] == 0
    assert audit.get("inv-1") is not None, "hồ sơ bị xoá cùng vết model"
    assert audit.tool_calls("inv-1") == []


def test_the_record_expires_eventually(store):
    clock = [1_000_000.0]
    audit = InvestigationAudit(store.conn, clock=lambda: clock[0])
    audit.record(_result(), validation={"checked": 1})
    clock[0] += (INVESTIGATION_RETENTION_DAYS + 1) * 86400
    assert audit.prune()["investigations_removed"] == 1
    assert audit.get("inv-1") is None


def test_pruning_leaves_no_orphan_claim_evidence(store):
    clock = [1_000_000.0]
    audit = InvestigationAudit(store.conn, clock=lambda: clock[0])
    audit.record(_result(), validation={"checked": 1})
    clock[0] += (INVESTIGATION_RETENTION_DAYS + 1) * 86400
    audit.prune()
    assert audit.conn.execute("SELECT COUNT(*) FROM claim_evidence").fetchone()[0] == 0
    assert audit.conn.execute(
        "SELECT COUNT(*) FROM investigation_claims").fetchone()[0] == 0
    assert audit.conn.execute(
        "SELECT COUNT(*) FROM investigation_hypotheses").fetchone()[0] == 0


def test_maintenance_prunes_ai_records(store):
    result = store.maintain(event_days=30)
    assert "ai_traces_deleted" in result
    assert "investigations_deleted" in result


# --- đường đi thật ---


def test_a_real_investigation_is_persisted_end_to_end(store):
    base = 1_000_000.0
    for event in (
        Event(base, "kernel", "process_exec",
              {"pid": 500, "start_ticks": "10", "comm": "curl"}),
        Event(base + 1, "kernel", "file_write",
              {"pid": 500, "start_ticks": "10", "path": "/tmp/payload"}),
        Event(base + 2, "kernel", "socket_connect",
              {"pid": 500, "start_ticks": "10", "remote_ip": "93.184.216.34",
               "remote_port": 443}),
    ):
        ingest(store, event)

    queries = EvidenceQueries(store.conn, caller="test")
    request = build_request(queries, "inc-real", [entity_id_for("process", "local:500:10")])
    orchestrator = InvestigationOrchestrator(queries, LocalDeterministicAnalyst())
    result, validation = run(orchestrator.investigate(request))

    audit = InvestigationAudit(store.conn)
    investigation_id = audit.record(result, validation=validation,
                                    tool_calls=orchestrator.tool_calls)
    stored = audit.get(investigation_id)
    assert stored["hypotheses"], "không lưu được giả thuyết nào"
    for hypothesis in stored["hypotheses"]:
        assert hypothesis["evidence_refs"]
        for ref in hypothesis["evidence_refs"]:
            assert queries.get_evidence(ref) is not None, "ref lưu lại không truy về đâu"


def test_the_agent_persists_before_broadcasting():
    """Lưu TRƯỚC khi phát đi: lần khởi động lại thường xảy ra ngay sau sự cố."""
    source = (ROOT / "shield/agent/__main__.py").read_text(encoding="utf-8")
    index = source.index("async def run_investigation")
    # Cắt tới hàm cấp cao kế tiếp, KHÔNG cắt theo số ký tự cố định: một cửa sổ
    # 3000 ký tự làm bài này đỏ khi hàm dài thêm, và cái đỏ đó không nói lên
    # điều gì về bất biến đang được canh.
    con_lai = source[index + 1:]
    ket = con_lai.find("\nasync def ")
    khac = con_lai.find("\ndef ")
    if khac != -1 and (ket == -1 or khac < ket):
        ket = khac
    block = source[index:index + 1 + (ket if ket != -1 else len(con_lai))]
    assert "audit.record" in block
    assert "payload = result.to_dict()" in block
    assert block.index("audit.record") < block.index("payload = result.to_dict()")


def test_a_storage_failure_never_breaks_the_investigation():
    """Không lưu được hồ sơ không được làm hỏng lượt điều tra: kết quả vẫn phải
    tới được người dùng."""
    source = (ROOT / "shield/agent/__main__.py").read_text(encoding="utf-8")
    index = source.index("audit = InvestigationAudit(store.conn)")
    block = source[index:index + 1200]
    assert "except (sqlite3.DatabaseError, ValueError)" in block
