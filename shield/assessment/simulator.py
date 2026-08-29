"""Non-invasive, in-memory assessment simulator."""

from __future__ import annotations

import time
from dataclasses import dataclass

from shield.assessment.models import TestCase
from shield.common.models import Event, now


SAFE_SOURCES = frozenset({"assessment", "endpoint", "fim", "journal", "network"})


@dataclass
class Simulation:
    event: Event
    ground_truth: dict
    cleaned_up: bool = False

    async def cleanup(self) -> None:
        # No external state exists today. Keeping this mandatory lifecycle
        # hook makes future simulator adapters fail closed on cancellation.
        self.cleaned_up = True


class SafeSimulator:
    """Create tagged events without files, sockets, commands or privileges."""

    def create(self, case: TestCase, session_id: str, marker: str) -> Simulation:
        raw = case.event
        source = str(raw.get("source", "assessment"))
        if source not in SAFE_SOURCES:
            raise ValueError(f"assessment source is not allowlisted: {source}")
        data = {
            **raw.get("data", {}),
            "assessment_id": session_id,
            "test_id": case.id,
            "marker": marker,
            "synthetic": True,
        }
        return Simulation(
            Event(now(), source, str(raw["kind"]), data),
            {
                "session_id": session_id,
                "test_id": case.id,
                "marker": marker,
                "action": "inject_in_memory_event",
                "external_side_effects": False,
                "ts": time.time(),
            },
        )
