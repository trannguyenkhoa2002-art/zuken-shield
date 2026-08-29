"""Isolated-lab plans and deterministic release gates.

This module describes and evaluates privileged tests. It never starts a network
namespace or VM unless a separate, explicitly authorized harness does so.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class LabScenario:
    id: str
    isolation: str
    requires_root: bool
    validates: tuple[str, ...]


DEFAULT_LAB = (
    LabScenario("collector-process", "disposable-vm", False, ("kernel telemetry", "process tree")),
    LabScenario("firewall-rollback", "network-namespace", True, ("block", "management channel", "rollback")),
    LabScenario("quarantine-crash", "disposable-vm", True, ("quarantine", "restart", "restore")),
    LabScenario("authorized-network-detections", "network-namespace", True, ("port scan", "DNS", "brute force")),
    LabScenario("event-flood-soak", "disposable-vm", False, ("backpressure", "retention", "resource limits")),
)


def lab_manifest() -> list[dict]:
    return [asdict(item) for item in DEFAULT_LAB]


def evaluate_release_gate(results: list[dict], required: tuple[str, ...] | None = None) -> dict:
    required = required or tuple(item.id for item in DEFAULT_LAB)
    by_id = {str(item.get("id")): item for item in results}
    missing = [item for item in required if item not in by_id]
    failed = [item for item in required if item in by_id and by_id[item].get("status") != "passed"]
    metrics = [item for item in results if item.get("id") in required]
    return {"passed": not missing and not failed, "missing": missing, "failed": failed,
            "required": list(required), "results": metrics}
