from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

VALID_STATUSES = {"passed", "failed", "inconclusive", "skipped"}
_SAFE_ID = re.compile(r"^[a-zA-Z0-9_.-]{1,80}$")


@dataclass(frozen=True)
class TestCase:
    id: str
    title: str
    event: dict
    expected_event_kinds: tuple[str, ...]
    expected_rule_ids: tuple[str, ...]
    risk_min: int = 0
    max_latency_ms: float = 2000
    timeout_s: float = 5

    @classmethod
    def from_dict(cls, raw: dict) -> "TestCase":
        required = {"id", "title", "event", "expected_event_kinds", "expected_rule_ids"}
        if not required.issubset(raw) or not isinstance(raw["event"], dict):
            raise ValueError("invalid assessment test case")
        if not _SAFE_ID.fullmatch(str(raw.get("id", ""))):
            raise ValueError("invalid assessment test id")
        if raw["event"].get("kind") is None or not isinstance(raw["event"].get("data", {}), dict):
            raise ValueError("test event requires kind and data")
        timeout = float(raw.get("timeout_s", 5))
        if not 0.1 <= timeout <= 60:
            raise ValueError("test timeout outside safe range")
        return cls(
            str(raw["id"]), str(raw["title"]), dict(raw["event"]),
            tuple(map(str, raw["expected_event_kinds"])), tuple(map(str, raw["expected_rule_ids"])),
            max(0, min(100, int(raw.get("risk_min", 0)))),
            max(1, float(raw.get("max_latency_ms", 2000))), timeout,
        )


@dataclass(frozen=True)
class AssessmentProfile:
    id: str
    version: int
    authorized_local_only: bool
    tests: tuple[TestCase, ...]

    @classmethod
    def load(cls, path: Path) -> "AssessmentProfile":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 1 or not raw.get("authorized_local_only"):
            raise ValueError("assessment profile must be schema v1 and local-only")
        tests = tuple(TestCase.from_dict(item) for item in raw.get("tests", []))
        if not tests or len(tests) > 100 or len({test.id for test in tests}) != len(tests):
            raise ValueError("profile requires unique tests")
        return cls(str(raw["id"]), int(raw.get("version", 1)), True, tests)


@dataclass(frozen=True)
class TestResult:
    test_id: str
    status: str
    started_ts: float
    finished_ts: float
    latency_ms: float | None
    assertions: tuple[dict, ...]
    alerts: tuple[dict, ...] = ()
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AssessmentResult:
    session_id: str
    profile_id: str
    started_ts: float
    finished_ts: float
    results: tuple[TestResult, ...]
    ground_truth: tuple[dict, ...]

    @classmethod
    def create(cls, profile_id: str, started_ts: float, results: list[TestResult], ground_truth: list[dict]):
        return cls(uuid.uuid4().hex, profile_id, started_ts, time.time(), tuple(results), tuple(ground_truth))

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def counts(self) -> dict[str, int]:
        return {status: sum(r.status == status for r in self.results) for status in VALID_STATUSES}
