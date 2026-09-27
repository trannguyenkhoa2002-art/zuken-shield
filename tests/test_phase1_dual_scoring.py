"""Giai đoạn 1 — Behavior Risk và Evidence Confidence là HAI con số.

Tiêu chí nghiệm thu (mỗi bài dưới đây là một tiêu chí):

- Alert brute force SSH chưa thấy đăng nhập thành công: có Risk, Confidence
  60/100, và "còn thiếu" liệt kê đúng đăng nhập thành công + phiên đặc quyền.
- Fact lịch sử đọc từ DB THẬT đổi Confidence mà KHÔNG đổi Risk.
- Rule chưa có mô hình không được bịa danh sách thiếu (`basis=generic`).
- Hai con số đi hết đường ống: scoring -> Alert -> SQLite -> recent_alerts ->
  UI text, sống qua dedupe và migration DB cũ.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time

from shield.agent.bus import Bus
from shield.agent.store import Store
from shield.common.models import Alert, Event
from shield.security import evidence_model
from shield.security.evidence_model import EVIDENCE_MODELS, STORE_FACTS, confidence_cell, describe
from shield.security.scoring import RiskContext, RiskScorer


def _bruteforce(src="203.0.113.7", fails=25, ts=None) -> Alert:
    return Alert(ts or time.time(), "LOCAL_SSH_BRUTEFORCE", "warning", "SSH brute force", "detail",
                 src, evidence={"src_ip": src, "fail_count": fails, "window_min": 10})


def _journal(store: Store, kind: str, data: dict, ts: float) -> None:
    store.insert_event(Event(ts, "journal", kind, data))
    store.conn.commit()


# --- mô hình ---------------------------------------------------------------


def test_every_model_sums_to_100_and_every_fact_can_be_produced():
    producible = set(STORE_FACTS)
    samples = [
        _bruteforce(fails=25),
        Alert(0, "SCAN_PORTSCAN", "warning", "", "", "x",
              evidence={"src_ip": "x", "ports": list(range(12)), "acked_ports_matched": [22],
                        "ack_source": "packet"}),
        Alert(0, "MITM_GATEWAY_MAC_CHANGED", "critical", "", "", "gw",
              evidence={"baseline_mac": "aa", "observed_mac": "bb"}),
        Alert(0, "MITM_ARP_CONFLICT", "critical", "", "", "ip", evidence={"macs": ["aa", "bb"]}),
    ]
    for alert in samples:
        producible |= evidence_model.alert_facts(alert, trusted=False, repetition=3)
    for rule, model in EVIDENCE_MODELS.items():
        assert sum(item.weight for item in model) == 100, rule
        dead = {item.fact for item in model} - producible
        assert not dead, f"{rule}: fact không có nguồn nào sinh ra: {dead}"


def test_ssh_bruteforce_without_success_reports_risk_confidence_and_what_is_missing():
    assessment = RiskScorer().assess(_bruteforce(), RiskContext())
    confidence = assessment.evidence_confidence
    assert 0 < assessment.score <= 100
    assert confidence.basis == "model:LOCAL_SSH_BRUTEFORCE"
    assert confidence.score == 60
    assert confidence.missing == ("login_succeeded_from_source", "privileged_session_from_source")


def test_confidence_is_independent_of_risk():
    scorer = RiskScorer()
    alert = _bruteforce()
    without = scorer.assess(alert, RiskContext())
    with_login = scorer.assess(alert, RiskContext(), {"login_succeeded_from_source"})
    assert with_login.score == without.score, "fact bằng chứng không được đổi mức rủi ro hành vi"
    assert with_login.evidence_confidence.score == 85
    assert with_login.evidence_confidence.missing == ("privileged_session_from_source",)


def test_trusted_source_is_reported_as_missing_evidence_not_hidden():
    confidence = RiskScorer().assess(_bruteforce(), RiskContext(trusted=True)).evidence_confidence
    assert "source_untrusted" in confidence.missing
    assert confidence.score == 50


def test_unmodelled_rules_do_not_invent_missing_evidence():
    alert = Alert(time.time(), "LOCAL_SUDO_FAIL", "warning", "sudo", "", "alice",
                  evidence={"user": "alice"})
    confidence = RiskScorer().assess(alert).evidence_confidence
    assert confidence.basis == "generic"
    assert confidence.missing == () and confidence.observed == ()
    assert 0 <= confidence.score <= 100


# --- fact lịch sử từ DB thật ----------------------------------------------


def test_store_facts_find_a_successful_root_login_from_the_same_source(tmp_path):
    store = Store(tmp_path / "s.db")
    now_ts = time.time()
    _journal(store, "ssh_login", {"user": "root", "src_ip": "203.0.113.7"}, now_ts - 30)
    facts = store.evidence_facts(_bruteforce(ts=now_ts))
    assert facts == {"login_succeeded_from_source", "privileged_session_from_source"}
    assert RiskScorer().assess(_bruteforce(ts=now_ts), RiskContext(), facts).evidence_confidence.score == 100


def test_store_facts_ignore_other_sources_and_old_history(tmp_path):
    store = Store(tmp_path / "s.db")
    now_ts = time.time()
    _journal(store, "ssh_login", {"user": "root", "src_ip": "198.51.100.1"}, now_ts - 30)
    _journal(store, "ssh_login", {"user": "root", "src_ip": "203.0.113.7"}, now_ts - 2 * 3600)
    assert store.evidence_facts(_bruteforce(ts=now_ts)) == set()


def test_portscan_followed_by_ssh_attempts_is_a_store_fact(tmp_path):
    store = Store(tmp_path / "s.db")
    now_ts = time.time()
    _journal(store, "ssh_failed_password", {"src_ip": "203.0.113.9"}, now_ts - 5)
    scan = Alert(now_ts, "SCAN_PORTSCAN", "warning", "", "", "203.0.113.9",
                 evidence={"src_ip": "203.0.113.9", "ports": list(range(15))})
    assert "followed_by_auth_attempts" in store.evidence_facts(scan)


# --- đi hết đường ống -------------------------------------------------------


def test_alert_round_trips_both_scores():
    alert = Alert(1.0, "R", "info", "t", "d", "s", risk_score=82, evidence_confidence=61,
                  evidence_assessment={"basis": "model:R", "missing": ["x"]})
    again = Alert.from_dict(json.loads(json.dumps(alert.to_dict())))
    assert again.evidence_confidence == 61
    assert again.evidence_assessment["missing"] == ["x"]
    assert Alert.from_dict({"ts": 1, "rule_id": "R", "severity": "info", "title": "", "detail": "",
                            "subject": ""}).evidence_confidence == -1


def test_store_persists_confidence_and_dedupe_keeps_the_latest_assessment(tmp_path):
    store = Store(tmp_path / "s.db")
    first = Alert(time.time(), "LOCAL_SSH_BRUTEFORCE", "warning", "t", "d", "203.0.113.7",
                  risk_score=70, evidence_confidence=60, evidence_assessment={"basis": "m", "missing": ["a"]})
    store.insert_alert(first)
    later = Alert(time.time() + 1, "LOCAL_SSH_BRUTEFORCE", "warning", "t", "d", "203.0.113.7",
                  risk_score=65, evidence_confidence=85, evidence_assessment={"basis": "m", "missing": []})
    store.insert_alert(later)
    rows = store.recent_alerts()
    assert len(rows) == 1
    assert rows[0]["risk_score"] == 70, "risk giữ mức cao nhất như trước"
    assert rows[0]["evidence_confidence"] == 85, "confidence là lần đánh giá mới nhất"
    assert rows[0]["evidence_assessment"]["missing"] == []


def test_an_old_database_migrates_with_not_assessed_markers(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, rule_id TEXT NOT NULL,
            severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, subject TEXT NOT NULL,
            evidence TEXT NOT NULL, playbook TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1);
        INSERT INTO alerts (ts, rule_id, severity, title, detail, subject, evidence, playbook)
            VALUES (1, 'LEGACY', 'info', 't', 'd', 's', '{}', '[]');
    """)
    conn.commit()
    conn.close()
    store = Store(path, allow_migration=True)
    row = store.recent_alerts()[0]
    assert row["evidence_confidence"] == -1, "dòng cũ là CHƯA ĐÁNH GIÁ, không được gán điểm"
    assert confidence_cell(row) == "—"


def test_live_pipeline_scores_and_stores_both_numbers(tmp_path):
    from shield.agent.__main__ import run_alert_consumer

    class IpcRecorder:
        def __init__(self):
            self.messages = []

        async def broadcast(self, message_type, data):
            self.messages.append((message_type, data))

    async def exercise():
        store = Store(tmp_path / "live.db")
        now_ts = time.time()
        _journal(store, "ssh_login", {"user": "alice", "src_ip": "203.0.113.7"}, now_ts - 10)
        alert_bus, ipc = Bus(), IpcRecorder()
        task = asyncio.create_task(run_alert_consumer(alert_bus, store, ipc))
        await asyncio.sleep(0)
        await alert_bus.publish(_bruteforce(ts=now_ts))
        for _ in range(200):
            if store.recent_alerts():
                break
            await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return store.recent_alerts(), ipc.messages

    rows, messages = asyncio.run(exercise())
    assert rows, "alert không tới được database"
    row = rows[0]
    assert row["risk_score"] > 0
    assert row["evidence_confidence"] == 85
    assert row["evidence_assessment"]["missing"] == ["privileged_session_from_source"]
    broadcast = [data for kind, data in messages if kind == "alert"]
    assert broadcast and broadcast[0]["evidence_confidence"] == 85


def test_the_analyst_text_names_what_is_missing_in_both_languages():
    row = {"risk_score": 82, "evidence_confidence": 60,
           "evidence_assessment": RiskScorer().assess(_bruteforce()).evidence_confidence.to_dict()}
    en = describe(row, "en")
    vi = describe(row, "vi")
    assert "Behavior risk: 82/100" in en and "Evidence confidence: 60/100" in en
    assert "Missing evidence: Successful login from the same source; Privileged (root) session" in en
    assert "Còn thiếu bằng chứng: Đăng nhập thành công từ cùng nguồn" in vi
    assert confidence_cell(row) == "60/100"


def test_generic_confidence_is_labelled_as_an_estimate():
    row = {"risk_score": 40, "evidence_confidence": 62, "evidence_assessment": {"basis": "generic"}}
    assert confidence_cell(row) == "62/100*"
    assert "no evidence model" in describe(row, "en")


def test_a_short_burst_is_not_called_sustained():
    confidence = RiskScorer().assess(_bruteforce(fails=8), RiskContext()).evidence_confidence
    assert confidence.score == 45
    assert confidence.missing[0] == "sustained"
