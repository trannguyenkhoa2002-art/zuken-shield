"""Phép đo chất lượng phát hiện (mục 3.2).

Toàn bộ file này là số học thuần trên các con số đã đếm. Nó không biết detector
nào tồn tại, không đọc database, không có tham số điều chỉnh nào. Nhờ vậy khi
một con số trông sai, chỗ cần soi là runner hoặc corpus — không phải chỗ này.

Một quy tắc lặp lại trong cả file: **mẫu quá ít thì trả về `None`, không phải 0
hay 1.** Precision của một detector chưa từng kêu lần nào không phải 0% và cũng
không phải 100% — nó là chưa biết. Trả về một con số ở đó nghĩa là ai đó sẽ xếp
hạng detector theo nó.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# Số mẫu tối thiểu trước khi một tỉ lệ được coi là có nghĩa. Cùng con số với
# `decision/calibration.py` và có test khẳng định điều đó — hai ngưỡng khác
# nhau cho cùng một khái niệm là hai câu trả lời khác nhau cho cùng một câu hỏi.
MIN_SAMPLES = 20


@dataclass
class ConfusionMatrix:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return (self.true_positives + self.false_positives
                + self.true_negatives + self.false_negatives)

    @property
    def precision(self) -> float | None:
        """Trong những lần kêu, bao nhiêu lần đúng."""
        flagged = self.true_positives + self.false_positives
        return self.true_positives / flagged if flagged else None

    @property
    def recall(self) -> float | None:
        """Trong những thứ đáng kêu, bao nhiêu phần đã kêu."""
        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else None

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    def to_dict(self) -> dict:
        return {
            "true_positives": self.true_positives, "false_positives": self.false_positives,
            "true_negatives": self.true_negatives, "false_negatives": self.false_negatives,
            "total": self.total, "precision": self.precision, "recall": self.recall,
            "f1": self.f1, "enough_samples": self.total >= MIN_SAMPLES,
        }


@dataclass
class DetectorMetrics:
    rule_id: str
    matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, **self.matrix.to_dict()}


def false_positives_per_host_day(false_positives: int, hosts: int, days: float) -> float | None:
    """Con số người vận hành thật sự sống cùng.

    "Precision 92%" nghe ổn cho tới khi nó có nghĩa là 40 cảnh báo sai mỗi ngày
    trên mỗi máy — và khi đó không ai đọc cảnh báo nào nữa. Đây là phép đo cho
    biết hệ thống có dùng được không, tách khỏi phép đo cho biết nó có đúng không.
    """
    if hosts <= 0 or days <= 0:
        return None
    return false_positives / (hosts * days)


def expected_calibration_error(buckets) -> float | None:
    """ECE: khoảng cách giữa độ tự tin đã khai và tỉ lệ đúng thực tế.

    `buckets` là các bộ (độ_tự_tin_khai, số_đúng, tổng_số). Nếu một detector
    nói "0.9" và đúng 90% số lần thì ECE bằng 0. Nếu nó nói "0.9" và đúng 60%
    thì con số 0.9 đang nói dối, và ECE đo mức nói dối đó.

    Chỉ dùng KHI hệ thống thật sự khai ra một xác suất. Ở 2.0 Shield không
    khai — `evidence_strength` không phải xác suất — nên hàm này tồn tại để đo
    một provider bên ngoài nào đó có khai, chứ không phải để tự chấm mình.
    """
    total = sum(count for _, _, count in buckets)
    if total < MIN_SAMPLES:
        return None
    error = 0.0
    for confidence, correct, count in buckets:
        if count <= 0:
            continue
        accuracy = correct / count
        error += (count / total) * abs(float(confidence) - accuracy)
    return error


def merge_split_accuracy(expected_groups, actual_groups) -> float | None:
    """Incident ghép đúng hay chưa, đo bằng chỉ số Rand.

    Ghép hai sự việc không liên quan làm một, hay xé một sự việc thành năm, đều
    làm hỏng việc điều tra theo cách khó thấy: tổng số incident vẫn "hợp lý".
    Chỉ số Rand đếm theo TỪNG CẶP alert — cặp nào đáng chung nhóm mà bị tách,
    và cặp nào đáng tách mà bị gộp.
    """
    items = sorted(set(expected_groups) & set(actual_groups))
    if len(items) < 2:
        return None
    agree = pairs = 0
    for i, left in enumerate(items):
        for right in items[i + 1:]:
            pairs += 1
            same_expected = expected_groups[left] == expected_groups[right]
            same_actual = actual_groups[left] == actual_groups[right]
            agree += same_expected == same_actual
    return agree / pairs if pairs else None


@dataclass
class MetricsReport:
    """Toàn bộ số liệu của một lượt chạy corpus."""

    corpus_id: str = ""
    corpus_version: int = 0
    samples: int = 0
    per_detector: dict = field(default_factory=dict)
    overall: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    hosts: int = 1
    days: float = 1.0
    unsupported_claims: int = 0
    total_claims: int = 0
    tool_policy_violations: int = 0
    investigation_seconds: list = field(default_factory=list)
    incident_merge_accuracy: float | None = None
    failures: list = field(default_factory=list)

    @property
    def unsupported_claim_rate(self) -> float | None:
        return self.unsupported_claims / self.total_claims if self.total_claims else None

    @property
    def mean_time_to_investigate(self) -> float | None:
        if not self.investigation_seconds:
            return None
        return sum(self.investigation_seconds) / len(self.investigation_seconds)

    def to_dict(self) -> dict:
        return {
            "corpus_id": self.corpus_id, "corpus_version": self.corpus_version,
            "samples": self.samples,
            "overall": self.overall.to_dict(),
            "per_detector": {rule: metrics.to_dict()
                             for rule, metrics in sorted(self.per_detector.items())},
            "false_positives_per_host_day": false_positives_per_host_day(
                self.overall.false_positives, self.hosts, self.days),
            "unsupported_claim_rate": self.unsupported_claim_rate,
            "tool_policy_violations": self.tool_policy_violations,
            "mean_time_to_investigate_s": self.mean_time_to_investigate,
            "incident_merge_accuracy": self.incident_merge_accuracy,
            "failures": list(self.failures),
        }

    def gate_failures(self, *, min_precision: float = 0.0,
                      max_fp_per_host_day: float | None = None) -> list[str]:
        """Điều kiện nào KHÔNG đạt. Danh sách rỗng nghĩa là đạt.

        Trả về danh sách chứ không phải một boolean: "gate đỏ" không giúp ai
        sửa được gì, còn "detector X precision 0.41 trên 60 mẫu" thì giúp.
        """
        problems: list[str] = []
        if self.tool_policy_violations:
            problems.append(
                f"{self.tool_policy_violations} lần gọi tool ngoài chính sách "
                "(bắt buộc phải bằng 0)")
        rate = self.unsupported_claim_rate
        if rate is not None and rate > 0:
            problems.append(f"tỉ lệ khẳng định không có căn cứ: {rate:.1%} (bắt buộc 0%)")
        for rule_id, metrics in sorted(self.per_detector.items()):
            precision = metrics.matrix.precision
            if precision is None or metrics.matrix.total < MIN_SAMPLES:
                # Chưa đủ mẫu KHÔNG phải lỗi — nhưng cũng không phải đạt. Nói
                # ra thay vì im lặng cho qua.
                problems.append(f"{rule_id}: chưa đủ mẫu để đánh giá "
                                f"({metrics.matrix.total}/{MIN_SAMPLES})")
            elif precision < min_precision:
                problems.append(f"{rule_id}: precision {precision:.2f} "
                                f"dưới ngưỡng {min_precision:.2f} "
                                f"trên {metrics.matrix.total} mẫu")
        if max_fp_per_host_day is not None:
            rate = false_positives_per_host_day(
                self.overall.false_positives, self.hosts, self.days)
            if rate is not None and rate > max_fp_per_host_day:
                problems.append(f"{rate:.1f} cảnh báo sai mỗi máy mỗi ngày "
                                f"(trần {max_fp_per_host_day})")
        problems.extend(self.failures)
        return problems


def wilson_interval(correct: int, total: int, z: float = 1.96) -> tuple[float, float] | None:
    """Khoảng tin cậy cho một tỉ lệ. Cùng công thức với calibration.py."""
    if total < MIN_SAMPLES:
        return None
    p = correct / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))
