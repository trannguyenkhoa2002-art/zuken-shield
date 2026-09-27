"""Giai đoạn 2 — Vùng xám: đáng nghi nhưng chưa đủ bằng chứng, KHÔNG bị giấu.

Tiêu chí nghiệm thu:

- Near-miss của detector (3/5 lần SSH sai, 8/15 cổng) được ghi đúng MỘT lần
  vào vùng xám và KHÔNG thành alert, thông báo hay incident.
- Alert có Risk cao nhưng Confidence thấp vẫn là alert, VÀ có mục vùng xám
  "low_confidence" liệt kê bằng chứng còn thiếu. Đủ bằng chứng thì không.
- Alert bị policy tắt tiếng hiện trong vùng xám với lý do.
- Chỉ người (principal IPC) quyết định; nâng lên tạo incident có lý do
  `analyst_promoted` và audit; không quyết định hai lần; AI không có đường.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from shield.agent import notifier
from shield.agent.bus import Bus
from shield.agent.detectors.local_log import SSH_BRUTEFORCE_THRESHOLD, LocalLogDetector
from shield.agent.detectors.portscan import PortscanDetector
from shield.agent.store import Store
from shield.common.models import Alert, Event
from shield.security.gray_zone import GrayThresholds, GrayZoneStore, classify
from shield.ui import gray_zone_view

ROOT = Path(__file__).resolve().parent.parent
PRINCIPAL = "uid=1000:pid=4242:client=test"


class IpcRecorder:
    def __init__(self):
        self.messages = []
        self.sent = []

    async def broadcast(self, kind, data):
        self.messages.append((kind, data))

    async def send_to(self, client_id, kind, data):
        self.sent.append((kind, data))
        return True


def _ssh_fail(src="203.0.113.7") -> Event:
    return Event(time.time(), "journal", "ssh_failed_password", {"src_ip": src})


def _run_pipeline(store: Store, alerts: list[Alert], monkeypatch) -> tuple[IpcRecorder, list]:
    from shield.agent.__main__ import run_alert_consumer

    notified = []

    async def fake_notify(alert, force=False):
        notified.append(alert.rule_id)

    monkeypatch.setattr(notifier, "notify", fake_notify)

    async def exercise():
        bus, ipc = Bus(), IpcRecorder()
        task = asyncio.create_task(run_alert_consumer(bus, store, ipc))
        await asyncio.sleep(0)
        for alert in alerts:
            await bus.publish(alert)
        for _ in range(300):
            await asyncio.sleep(0.01)
            if len([m for m in ipc.messages if m[0] in ("alert", "gray_zone_updated")]) >= len(alerts):
                break
        await asyncio.sleep(0.05)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return ipc

    return asyncio.run(exercise()), notified


# --- detector near-miss -----------------------------------------------------


def test_ssh_near_miss_is_emitted_once_then_the_real_alert_at_threshold(tmp_path):
    detector = LocalLogDetector(Store(tmp_path / "s.db"))
    outputs = [detector.handle_event(_ssh_fail()) for _ in range(SSH_BRUTEFORCE_THRESHOLD)]
    candidates = [a for out in outputs for a in out if "gray_zone" in a.evidence]
    real = [a for out in outputs for a in out if "gray_zone" not in a.evidence]
    assert len(candidates) == 1 and candidates[0].evidence["fail_count"] == 3
    assert len(real) == 1 and real[0].evidence["fail_count"] == SSH_BRUTEFORCE_THRESHOLD


def test_portscan_near_miss_at_half_threshold(tmp_path):
    detector = PortscanDetector(Store(tmp_path / "s.db"))
    outputs = []
    for port in range(1, 10):
        outputs += detector.handle_event(
            Event(time.time(), "packet", "tcp_syn", {"src_ip": "198.51.100.4", "dst_port": port}))
    assert len(outputs) == 1
    assert outputs[0].evidence["gray_zone"]["observed"] == 8


# --- đường ống ----------------------------------------------------------------


def test_a_near_miss_reaches_the_gray_zone_but_never_becomes_an_alert(tmp_path, monkeypatch):
    store = Store(tmp_path / "s.db")
    detector = LocalLogDetector(store)
    candidate = [a for _ in range(3) for a in detector.handle_event(_ssh_fail())][0]
    ipc, notified = _run_pipeline(store, [candidate], monkeypatch)
    entries = GrayZoneStore(store.conn).entries()
    assert [e["kind"] for e in entries] == ["below_threshold"]
    assert "3 failed logins" in entries[0]["reason"]
    assert store.recent_alerts() == [], "near-miss không được thành alert"
    assert not [m for m in ipc.messages if m[0] == "alert"]
    assert notified == []
    assert store.conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0


def test_high_risk_low_confidence_alert_is_kept_and_listed_with_missing_evidence(tmp_path, monkeypatch):
    store = Store(tmp_path / "s.db")
    alert = Alert(time.time(), "LOCAL_SSH_BRUTEFORCE", "critical", "SSH brute force", "d", "203.0.113.7",
                  evidence={"src_ip": "203.0.113.7", "fail_count": 25})
    _run_pipeline(store, [alert], monkeypatch)
    rows = store.recent_alerts()
    assert len(rows) == 1, "alert vẫn phải tồn tại như trước"
    entries = GrayZoneStore(store.conn).entries()
    assert len(entries) == 1 and entries[0]["kind"] == "low_confidence"
    assert entries[0]["evidence_confidence"] == 60
    assert entries[0]["risk_score"] >= 40
    assert entries[0]["missing"] == ["login_succeeded_from_source", "privileged_session_from_source"]
    assert entries[0]["alert_id"] > 0


def test_enough_evidence_keeps_the_alert_out_of_the_gray_zone(tmp_path, monkeypatch):
    store = Store(tmp_path / "s.db")
    store.insert_event(Event(time.time() - 5, "journal", "ssh_login",
                             {"user": "root", "src_ip": "203.0.113.7"}))
    store.conn.commit()
    alert = Alert(time.time(), "LOCAL_SSH_BRUTEFORCE", "critical", "t", "d", "203.0.113.7",
                  evidence={"src_ip": "203.0.113.7", "fail_count": 25})
    _run_pipeline(store, [alert], monkeypatch)
    assert store.recent_alerts()[0]["evidence_confidence"] == 100
    assert GrayZoneStore(store.conn).entries() == []


def test_suppressed_alerts_are_visible_in_the_gray_zone(tmp_path, monkeypatch):
    store = Store(tmp_path / "s.db")
    store.add_suppression("LOCAL_SUDO_FAIL", "*", time.time() + 3600, "known admin script")
    alert = Alert(time.time(), "LOCAL_SUDO_FAIL", "warning", "sudo", "d", "alice", evidence={"user": "alice"})
    ipc, notified = _run_pipeline(store, [alert], monkeypatch)
    entries = GrayZoneStore(store.conn).entries()
    assert [e["kind"] for e in entries] == ["suppressed"]
    assert "known admin script" in entries[0]["reason"]
    assert notified == []


def test_repeated_signals_merge_into_one_open_entry(tmp_path):
    gray = GrayZoneStore(Store(tmp_path / "s.db").conn)
    alert = Alert(time.time(), "R", "info", "t", "d", "x", evidence={"gray_zone": {"reason": "r"}})
    first = gray.record(alert, "below_threshold", "r")
    second = gray.record(alert, "below_threshold", "r")
    assert first["entry_id"] == second["entry_id"] and second["count"] == 2


# --- quyết định của con người -----------------------------------------------


def _handle(store: Store, msg: dict, ipc: IpcRecorder) -> None:
    from shield.agent.__main__ import handle_command

    msg = dict(msg, request_id="r1", _peer={"client_id": "test", "uid": 1000, "pid": 4242})
    asyncio.run(handle_command(msg, store, None, None, Bus(), ipc, None, None, None, {}, None, None,
                               None, {}))


def test_promote_creates_an_analyst_incident_with_reason_and_audit(tmp_path):
    store = Store(tmp_path / "s.db")
    gray = GrayZoneStore(store.conn)
    entry = gray.record(Alert(time.time(), "SCAN_PORTSCAN", "info", "near scan", "d", "198.51.100.4",
                              risk_score=35, evidence={"gray_zone": {"reason": "8 ports"}}),
                        "below_threshold", "8 ports")
    ipc = IpcRecorder()
    _handle(store, {"cmd": "gray_zone_decide", "entry_id": entry["entry_id"], "decision": "promote",
                    "note": "same host scanned the NAS yesterday"}, ipc)
    decided = gray.get(entry["entry_id"])
    assert decided["state"] == "promoted"
    assert decided["decided_by"] == PRINCIPAL
    incident = store.list_incidents(limit=10)[0]
    assert incident["incident_id"] == decided["incident_id"]
    reasons = store.incident_correlation_reasons(incident["incident_id"])
    assert reasons[0]["reason_kind"] == "analyst_promoted"
    audit = store.conn.execute(
        "SELECT params FROM audit_log WHERE action_id='gray_zone_decide'").fetchone()
    assert audit and PRINCIPAL in audit[0]
    assert ("gray_zone_updated", {"entry": decided}) in ipc.messages


def test_a_decision_is_final_and_needs_a_principal(tmp_path):
    gray = GrayZoneStore(Store(tmp_path / "s.db").conn)
    entry = gray.record(Alert(time.time(), "R", "info", "t", "d", "x"), "suppressed", "r")
    with pytest.raises(ValueError):
        gray.decide(entry["entry_id"], "dismiss", principal="")
    with pytest.raises(ValueError):
        gray.decide(entry["entry_id"], "dismiss", principal="model")
    gray.decide(entry["entry_id"], "dismiss", principal=PRINCIPAL, note="false positive")
    with pytest.raises(ValueError):
        gray.decide(entry["entry_id"], "promote", principal=PRINCIPAL)


def test_rejected_decisions_are_reported_to_the_ui(tmp_path):
    store = Store(tmp_path / "s.db")
    ipc = IpcRecorder()
    _handle(store, {"cmd": "gray_zone_decide", "entry_id": "missing", "decision": "promote"}, ipc)
    assert ipc.sent and ipc.sent[0][0] == "command_error"


def test_no_model_or_automation_path_can_decide_a_gray_zone_entry():
    for path in (ROOT / "shield").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if ".decide(" in text and "gray" in text.lower():
            relative = path.relative_to(ROOT).as_posix()
            assert relative in {"shield/agent/__main__.py", "shield/security/gray_zone.py"}, relative
    ai_code = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "shield" / "ai").rglob("*.py"))
    assert "gray_zone" not in ai_code and "GrayZone" not in ai_code


def test_only_decided_old_entries_are_pruned(tmp_path):
    gray = GrayZoneStore(Store(tmp_path / "s.db").conn)
    old_ts = time.time() - 200 * 86400
    kept = gray.record(Alert(old_ts, "R1", "info", "t", "d", "a"), "suppressed", "r")
    gone = gray.record(Alert(old_ts, "R2", "info", "t", "d", "b"), "suppressed", "r")
    gray.decide(gone["entry_id"], "dismiss", principal=PRINCIPAL)
    assert gray.prune(time.time() - 90 * 86400) == 1
    assert gray.get(kept["entry_id"]) is not None, "mục chưa ai xem không được tự biến mất"


# --- ngưỡng và hiển thị --------------------------------------------------------


def test_thresholds_come_from_managed_configuration_and_are_clamped():
    assert GrayThresholds.from_env({}) == GrayThresholds(40, 70)
    assert GrayThresholds.from_env({"SHIELD_GRAY_MIN_RISK": "500",
                                    "SHIELD_CONFIRM_MIN_CONFIDENCE": "x"}) == GrayThresholds(100, 70)


def test_generic_rules_are_never_called_low_confidence():
    alert = Alert(0, "LOCAL_SUDO_FAIL", "warning", "t", "d", "x", risk_score=90,
                  evidence_confidence=10, evidence_assessment={"basis": "generic"})
    assert classify(alert, suppressed_reason=None, thresholds=GrayThresholds()) is None


def test_the_table_row_names_missing_evidence_in_both_languages():
    entry = {"last_seen": 0, "kind": "low_confidence", "rule_id": "LOCAL_SSH_BRUTEFORCE",
             "subject": "203.0.113.7", "risk_score": 82, "evidence_confidence": 60, "count": 2,
             "reason": "r", "missing": ["login_succeeded_from_source"]}
    assert gray_zone_view.row_values(entry, "en")[-1] == "Successful login from the same source"
    assert gray_zone_view.row_values(entry, "vi")[1] == "Thiếu bằng chứng"
    assert len(gray_zone_view.headers("vi")) == len(gray_zone_view.row_values(entry, "vi"))
