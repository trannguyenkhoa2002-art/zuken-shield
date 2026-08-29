from __future__ import annotations

import asyncio
import json
import zipfile
from pathlib import Path

import pytest

from shield.agent.detectors.endpoint import EndpointDetector
from shield.agent.__main__ import run_alert_consumer, run_event_consumer
from shield.agent.bus import Bus
from shield.agent.store import Store
from shield.assessment.cli import verify_bundle
from shield.assessment.exporters import coverage, export_evidence_bundle, export_junit, export_sarif
from shield.assessment.models import AssessmentProfile, TestCase as AssessmentTestCase
from shield.assessment.replay import replay
from shield.assessment.runner import AssessmentRunner
from shield.assessment.simulator import SafeSimulator
from shield.common.models import Event
from shield.security.rules import RuleDetector


ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "shield" / "assessment" / "default-profile.json"
RULES = ROOT / "shield" / "rules" / "default.json"


def detectors() -> list:
    return [EndpointDetector(), RuleDetector.from_file(RULES)]


def test_bundled_safe_profile_passes_and_has_full_rule_coverage():
    profile = AssessmentProfile.load(PROFILE)
    result = asyncio.run(AssessmentRunner(detectors()).run(profile)).to_dict()
    assert {item["status"] for item in result["results"]} == {"passed"}
    assert coverage(result)["rule_coverage_percent"] == 100.0
    assert all(not item["external_side_effects"] for item in result["ground_truth"])


def test_simulator_rejects_non_allowlisted_source():
    case = AssessmentTestCase.from_dict({
        "id": "unsafe-source", "title": "invalid",
        "event": {"source": "remote", "kind": "x", "data": {}},
        "expected_event_kinds": ["x"], "expected_rule_ids": [],
    })
    with pytest.raises(ValueError, match="not allowlisted"):
        SafeSimulator().create(case, "session", "marker")


def test_profile_requires_explicit_local_authorization(tmp_path: Path):
    raw = json.loads(PROFILE.read_text())
    raw["authorized_local_only"] = False
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="local-only"):
        AssessmentProfile.load(path)


def test_replay_never_executes_response_actions():
    event = Event(1.0, "assessment", "listener_opened", {"ip": "127.0.0.1", "port": 445})
    result = replay([event], detectors())
    assert result["alerts"]
    assert result["response_actions_executed"] == 0


def test_exports_junit_sarif_and_signed_evidence(tmp_path: Path):
    result = asyncio.run(AssessmentRunner(detectors()).run(AssessmentProfile.load(PROFILE))).to_dict()
    export_junit(result, tmp_path / "junit.xml")
    export_sarif(result, tmp_path / "result.sarif")
    export_evidence_bundle(result, tmp_path / "evidence.zip", b"test-secret")
    assert (tmp_path / "junit.xml").read_text().startswith("<?xml")
    assert json.loads((tmp_path / "result.sarif").read_text())["version"] == "2.1.0"
    assert verify_bundle(tmp_path / "evidence.zip", b"test-secret") == (True, "verified (HMAC signed)")
    assert verify_bundle(tmp_path / "evidence.zip", b"wrong")[0] is False
    with zipfile.ZipFile(tmp_path / "evidence.zip") as bundle:
        assert set(bundle.namelist()) == {"assessment.json", "manifest.json"}


def test_assessment_result_and_ground_truth_persist(tmp_path: Path):
    store = Store(path=tmp_path / "shield.db")
    try:
        result = asyncio.run(AssessmentRunner(detectors(), store=store).run(AssessmentProfile.load(PROFILE)))
        assert store.recent_assessments(1)[0]["session_id"] == result.session_id
        count = store.conn.execute(
            "SELECT COUNT(*) FROM assessment_ground_truth WHERE session_id=?", (result.session_id,)
        ).fetchone()[0]
        assert count == len(result.results)
    finally:
        store.close()


def test_live_pipeline_persists_assessment_without_operational_broadcast(tmp_path: Path):
    class IpcRecorder:
        def __init__(self):
            self.messages = []

        async def broadcast(self, message_type, data):
            self.messages.append((message_type, data))

    async def exercise():
        store = Store(path=tmp_path / "live.db")
        event_bus, alert_bus, ipc = Bus(), Bus(), IpcRecorder()
        consumers = [
            asyncio.create_task(run_event_consumer(event_bus, alert_bus, store, detectors(), ipc)),
            asyncio.create_task(run_alert_consumer(alert_bus, store, ipc)),
        ]
        await asyncio.sleep(0)
        try:
            result = await AssessmentRunner([], event_bus=event_bus, store=store).run(
                AssessmentProfile.load(PROFILE)
            )
            assert all(item.status == "passed" for item in result.results)
            assert not [item for item in ipc.messages if item[0] == "alert"]
        finally:
            for task in consumers:
                task.cancel()
            await asyncio.gather(*consumers, return_exceptions=True)
            store.close()

    asyncio.run(exercise())


def test_replay_module_has_no_response_engine_dependency():
    source = (ROOT / "shield" / "assessment" / "replay.py").read_text()
    assert "shield.security.response" not in source
