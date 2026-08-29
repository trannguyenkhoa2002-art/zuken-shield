"""Chạy corpus ground-truth qua detector THẬT (mục 3.2).

Nguyên tắc: runner không mô phỏng detector. Nó bơm event vào đúng các detector
mà agent dùng, rồi đếm. Một bộ đo chạy trên detector giả chỉ đo được chính nó.

Corpus là dữ liệu tĩnh CÓ PHIÊN BẢN. Sửa một mẫu mà không tăng phiên bản nghĩa
là hai lần chạy khác nhau cùng khai là "corpus v3", và không ai đối chiếu được
kết quả cũ với kết quả mới.

Toàn bộ file này chạy offline: không mạng, không root, không đụng máy thật.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from shield.common.models import Alert, Event
from shield.evals.metrics import ConfusionMatrix, DetectorMetrics, MetricsReport

DATASET_DIR = Path(__file__).parent / "datasets"
_SAFE_ID = re.compile(r"^[a-zA-Z0-9_.-]{1,80}$")

# Nhóm mẫu bắt buộc phải có, lấy thẳng từ mục 3.2. Corpus thiếu một nhóm là
# corpus chưa hỏi một câu — và câu chưa hỏi thường là câu quan trọng nhất.
REQUIRED_CATEGORIES = frozenset({
    "normal_admin",
    "unusual_benign",
    "true_attack",
    "missing_telemetry",
    "duplicated_events",
    "out_of_order_events",
    "forged_syslog",
    "compromised_probe",
    "prompt_injection",
    "poisoned_intel",
    "response_failure",
})


@dataclass(frozen=True)
class Sample:
    id: str
    category: str
    # `malicious` nghĩa là ĐÁNG kêu; `benign` nghĩa là KHÔNG đáng kêu.
    # Không có "có thể" — một mẫu không ai dán nhãn được thì không thuộc về
    # corpus đo lường, nó thuộc về danh sách câu hỏi mở.
    label: str
    events: tuple[dict, ...]
    expected_rule_ids: tuple[str, ...] = ()
    note: str = ""

    @classmethod
    def parse(cls, raw: dict) -> "Sample":
        if not isinstance(raw, dict):
            raise ValueError("mẫu phải là object")
        if not _SAFE_ID.fullmatch(str(raw.get("id", ""))):
            raise ValueError(f"id mẫu không hợp lệ: {raw.get('id')!r}")
        if raw.get("label") not in {"malicious", "benign"}:
            raise ValueError(f"{raw.get('id')}: label phải là malicious hoặc benign")
        if raw.get("category") not in REQUIRED_CATEGORIES:
            raise ValueError(f"{raw.get('id')}: nhóm không hợp lệ: {raw.get('category')!r}")
        events = raw.get("events") or []
        if not isinstance(events, list) or not events:
            raise ValueError(f"{raw.get('id')}: mẫu phải có ít nhất một event")
        for event in events:
            if not isinstance(event, dict) or "kind" not in event:
                raise ValueError(f"{raw.get('id')}: event thiếu kind")
        return cls(
            id=str(raw["id"]), category=str(raw["category"]), label=str(raw["label"]),
            events=tuple(dict(e) for e in events),
            expected_rule_ids=tuple(str(r) for r in raw.get("expected_rule_ids", ())),
            note=str(raw.get("note", ""))[:500],
        )


@dataclass(frozen=True)
class Corpus:
    id: str
    version: int
    samples: tuple[Sample, ...]

    @classmethod
    def load(cls, path: Path) -> "Corpus":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("corpus phải là object JSON")
        version = int(raw.get("version", 0))
        if version < 1:
            raise ValueError("corpus phải có version >= 1")
        samples = tuple(Sample.parse(item) for item in raw.get("samples", []))
        if not samples:
            raise ValueError("corpus rỗng")
        ids = [sample.id for sample in samples]
        if len(set(ids)) != len(ids):
            raise ValueError("id mẫu trùng nhau")
        return cls(str(raw.get("id", "")), version, samples)

    def missing_categories(self) -> list[str]:
        """Nhóm nào chưa có mẫu nào. Corpus thiếu một nhóm là corpus chưa hỏi
        một câu."""
        present = {sample.category for sample in self.samples}
        return sorted(REQUIRED_CATEGORIES - present)


def default_corpus() -> Corpus:
    return Corpus.load(DATASET_DIR / "detection-corpus.json")


def run_corpus(corpus: Corpus, detectors, *, hosts: int = 1, days: float = 1.0) -> MetricsReport:
    """Bơm từng mẫu qua detector và đếm.

    Detector được dựng lại cho MỖI mẫu bởi chỗ gọi nếu chúng có trạng thái —
    runner không tự dựng, vì nó không được biết detector nào cần store nào.
    """
    report = MetricsReport(corpus_id=corpus.id, corpus_version=corpus.version,
                           samples=len(corpus.samples), hosts=hosts, days=days)
    report.failures.extend(
        f"corpus thiếu nhóm mẫu: {name}" for name in corpus.missing_categories())

    for sample in corpus.samples:
        started = time.monotonic()
        alerts: list[Alert] = []
        for raw in sample.events:
            event = Event(
                ts=float(raw.get("ts", 1_000_000.0)),
                source=str(raw.get("source", "eval")),
                kind=str(raw["kind"]),
                data=dict(raw.get("data") or {}),
                origin=str(raw.get("origin", "local")),
                trust=str(raw.get("trust", "local")),
            )
            for detector in detectors:
                try:
                    alerts.extend(detector.handle_event(event))
                except Exception as exc:  # noqa: BLE001 — detector lỗi là một phát hiện
                    report.failures.append(
                        f"{sample.id}: {type(detector).__name__} ném {type(exc).__name__}: {exc}")
        report.investigation_seconds.append(time.monotonic() - started)

        fired = {alert.rule_id for alert in alerts}
        _count(report, sample, fired)
    return report


def _count(report: MetricsReport, sample: Sample, fired: set[str]) -> None:
    """Đếm một mẫu vào ma trận nhầm lẫn, tổng thể và theo từng detector."""
    if sample.label == "malicious":
        # Với mẫu độc, "đúng" nghĩa là kêu — và nếu mẫu ghi rõ rule mong đợi
        # thì phải kêu ĐÚNG rule đó. Kêu đúng lý do sai vẫn là kêu sai.
        expected = set(sample.expected_rule_ids)
        hit = bool(fired & expected) if expected else bool(fired)
        if hit:
            report.overall.true_positives += 1
        else:
            report.overall.false_negatives += 1
        for rule_id in sorted(expected or fired):
            metrics = report.per_detector.setdefault(rule_id, DetectorMetrics(rule_id))
            if rule_id in fired:
                metrics.matrix.true_positives += 1
            else:
                metrics.matrix.false_negatives += 1
    else:
        if fired:
            report.overall.false_positives += 1
        else:
            report.overall.true_negatives += 1
        for rule_id in sorted(fired):
            metrics = report.per_detector.setdefault(rule_id, DetectorMetrics(rule_id))
            metrics.matrix.false_positives += 1
        # Detector nào ĐƯỢC MONG ĐỢI im lặng mà im lặng thật thì tính là đúng.
        for rule_id in sorted(sample.expected_rule_ids):
            metrics = report.per_detector.setdefault(rule_id, DetectorMetrics(rule_id))
            if rule_id not in fired:
                metrics.matrix.true_negatives += 1


def empty_matrix() -> ConfusionMatrix:
    return ConfusionMatrix()
