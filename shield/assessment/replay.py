"""Pure event replay. This module has no response-engine imports."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from shield.common.models import Event
from shield.security.scoring import RiskScorer


def load_jsonl(path: Path, limit: int = 100_000) -> list[Event]:
    events = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if number > limit:
                raise ValueError("replay event limit exceeded")
            if not line.strip():
                continue
            events.append(Event.from_dict(json.loads(line)))
    return events


def replay(events: list[Event], detectors: list) -> dict:
    scorer = RiskScorer()
    alerts = []
    for event in events:
        for detector in detectors:
            for alert in detector.handle_event(event):
                assessment = scorer.assess(alert)
                alerts.append(replace(alert, risk_score=assessment.score,
                                evidence_strength=assessment.evidence_strength).to_dict())
    return {"events": len(events), "alerts": alerts, "response_actions_executed": 0}
