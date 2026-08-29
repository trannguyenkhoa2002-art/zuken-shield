"""Assessment runner with explicit ground truth, watchdog and assertions."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import replace

from shield.assessment.models import AssessmentProfile, AssessmentResult, TestResult
from shield.assessment.simulator import SafeSimulator
from shield.security.scoring import RiskScorer


class AssessmentRunner:
    def __init__(self, detectors: list, event_bus=None, store=None) -> None:
        self.detectors = tuple(detectors)
        self.event_bus, self.store = event_bus, store
        self.scorer = RiskScorer()
        self.simulator = SafeSimulator()

    async def run(self, profile: AssessmentProfile) -> AssessmentResult:
        started = time.time()
        session_id = uuid.uuid4().hex
        results, truth = [], []
        for case in profile.tests:
            results.append(await self._run_case(session_id, case, truth))
        result = AssessmentResult(session_id, profile.id, started, time.time(), tuple(results), tuple(truth))
        if self.store is not None:
            self.store.save_assessment_result(result.to_dict())
        return result

    async def _run_case(self, session_id, case, truth) -> TestResult:
        started = time.time()
        marker = uuid.uuid4().hex
        simulation = self.simulator.create(case, session_id, marker)
        event = simulation.event
        truth.append(simulation.ground_truth)
        alerts = []
        try:
            return await asyncio.wait_for(
                self._evaluate(case, event, marker, started, alerts),
                timeout=case.timeout_s,
            )
        except asyncio.TimeoutError:
            return TestResult(case.id, "inconclusive", started, time.time(), None, (), (), "watchdog timeout")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return TestResult(case.id, "inconclusive", started, time.time(), None, (), (), str(exc))
        finally:
            await simulation.cleanup()

    async def _evaluate(self, case, event, marker, started, alerts) -> TestResult:
        events = []
        if self.event_bus is not None and self.store is not None:
            await self.event_bus.publish(event)
            deadline = time.monotonic() + case.timeout_s
            while time.monotonic() < deadline:
                alerts = [a for a in self.store.recent_alerts(500) if (a.get("evidence") or {}).get("marker") == marker]
                events = [e for e in self.store.recent_events(limit=500) if (e.get("data") or {}).get("marker") == marker]
                if alerts and events:
                    break
                await asyncio.sleep(0.05)
        else:
            events = [event.to_dict()]
            for detector in self.detectors:
                for alert in detector.handle_event(event):
                    assessment = self.scorer.assess(alert)
                    alerts.append(replace(alert, risk_score=assessment.score,
                                    evidence_strength=assessment.evidence_strength).to_dict())
        latency = ((min((a["ts"] for a in alerts), default=time.time()) - started) * 1000) if alerts else None
        actual_kinds = {e["kind"] for e in events}
        actual_rules = {a["rule_id"] for a in alerts}
        peak_risk = max((int(a.get("risk_score", 0)) for a in alerts), default=0)
        assertions = (
            {"name": "event_kinds", "passed": set(case.expected_event_kinds).issubset(actual_kinds), "expected": list(case.expected_event_kinds), "actual": sorted(actual_kinds)},
            {"name": "rule_ids", "passed": set(case.expected_rule_ids).issubset(actual_rules), "expected": list(case.expected_rule_ids), "actual": sorted(actual_rules)},
            {"name": "risk_min", "passed": peak_risk >= case.risk_min, "expected": case.risk_min, "actual": peak_risk},
            {"name": "latency", "passed": latency is not None and latency <= case.max_latency_ms, "expected": case.max_latency_ms, "actual": latency},
        )
        status = "passed" if all(item["passed"] for item in assertions) else "failed"
        return TestResult(case.id, status, started, time.time(), latency, assertions, tuple(alerts))
