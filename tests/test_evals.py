"""Corpus ground-truth và bộ đo chất lượng phát hiện (mục 3.2).

Bộ đo này chạy mỗi lần commit, không phải mỗi quý. Một phép đo chỉ chạy khi có
người nhớ ra sẽ đo đúng một lần, ngay trước khi phát hành, và không ai biết con
số đã trôi đi từ lúc nào.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shield.evals.metrics import (
    MIN_SAMPLES,
    ConfusionMatrix,
    MetricsReport,
    expected_calibration_error,
    false_positives_per_host_day,
    merge_split_accuracy,
    wilson_interval,
)
from shield.evals.runner import (
    DATASET_DIR,
    Corpus,
    Sample,
    default_corpus,
    run_corpus,
)
from shield.security.mitre import BehaviorChainDetector
from shield.security.rules import RuleDetector

ROOT = Path(__file__).resolve().parent.parent


def _detectors():
    return [
        RuleDetector.from_directory(ROOT / "shield/rules"),
        BehaviorChainDetector(),
    ]


# --- corpus ---


def test_the_corpus_loads_and_is_versioned():
    corpus = default_corpus()
    assert corpus.version >= 1
    assert corpus.id


def test_the_corpus_covers_every_required_category():
    """Corpus thiếu một nhóm là corpus chưa hỏi một câu — và câu chưa hỏi
    thường là câu quan trọng nhất."""
    assert default_corpus().missing_categories() == []


def test_the_corpus_has_both_labels_in_useful_numbers():
    """Một corpus toàn mẫu độc đo được recall và không đo được gì khác."""
    samples = default_corpus().samples
    malicious = sum(1 for s in samples if s.label == "malicious")
    benign = sum(1 for s in samples if s.label == "benign")
    assert malicious >= 5 and benign >= 5


@pytest.mark.parametrize("raw", [
    {},
    {"id": "x", "label": "malicious"},
    {"id": "x", "label": "maybe", "category": "true_attack", "events": [{"kind": "k"}]},
    {"id": "x", "label": "malicious", "category": "khong_ton_tai", "events": [{"kind": "k"}]},
    {"id": "x", "label": "malicious", "category": "true_attack", "events": []},
    {"id": "x", "label": "malicious", "category": "true_attack", "events": [{}]},
    {"id": "../etc", "label": "malicious", "category": "true_attack", "events": [{"kind": "k"}]},
])
def test_a_malformed_sample_is_refused(raw):
    with pytest.raises(ValueError):
        Sample.parse(raw)


def test_there_is_no_maybe_label():
    """Một mẫu không ai dán nhãn được thì không thuộc về corpus đo lường; nó
    thuộc về danh sách câu hỏi mở."""
    for sample in default_corpus().samples:
        assert sample.label in {"malicious", "benign"}


def test_a_corpus_without_a_version_is_refused(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"id": "x", "samples": [
        {"id": "a", "label": "benign", "category": "normal_admin",
         "events": [{"kind": "k"}]}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="version"):
        Corpus.load(path)


def test_duplicate_sample_ids_are_refused(tmp_path):
    path = tmp_path / "c.json"
    sample = {"id": "a", "label": "benign", "category": "normal_admin",
              "events": [{"kind": "k"}]}
    path.write_text(json.dumps({"id": "x", "version": 1, "samples": [sample, sample]}),
                    encoding="utf-8")
    with pytest.raises(ValueError, match="trùng"):
        Corpus.load(path)


def test_the_dataset_file_is_committed():
    assert (DATASET_DIR / "detection-corpus.json").is_file()


# --- chạy corpus qua detector THẬT ---


def test_the_corpus_runs_clean_against_the_real_detectors():
    """Điều kiện đạt: không dương tính giả, không âm tính giả.

    Con số này là hợp đồng: nếu một thay đổi làm nó tụt, test đỏ ngay trong
    commit đó chứ không phải sáu tháng sau trên máy người dùng.
    """
    report = run_corpus(default_corpus(), _detectors(), hosts=1, days=1)
    matrix = report.overall
    assert matrix.false_positives == 0, f"dương tính giả: {matrix.to_dict()}"
    assert matrix.false_negatives == 0, f"âm tính giả: {matrix.to_dict()}"
    assert report.failures == [], report.failures


def test_a_package_manager_does_not_trip_the_behaviour_chain():
    """Mẫu này chính là lỗi corpus đã bắt được: chuỗi exec->write->connect kêu
    trên mỗi lượt `apt upgrade`, ngay khi telemetry file_write chảy thật."""
    corpus = default_corpus()
    sample = next(s for s in corpus.samples
                  if s.id == "normal.package-manager-writes-then-fetches")
    single = Corpus(corpus.id, corpus.version, (sample,))
    report = run_corpus(single, _detectors())
    assert report.overall.false_positives == 0


def test_a_failed_response_verification_is_never_silent():
    """Một hành động báo thành công rồi hoá ra không đổi trạng thái hệ thống
    phải kêu — đó là ba lời nói dối của Batch 2.0-P0."""
    corpus = default_corpus()
    sample = next(s for s in corpus.samples if s.category == "response_failure")
    single = Corpus(corpus.id, corpus.version, (sample,))
    report = run_corpus(single, _detectors())
    assert report.overall.false_negatives == 0


def test_a_detector_that_raises_is_reported_not_swallowed():
    class Exploding:
        def handle_event(self, event):
            raise RuntimeError("detector nổ")

    report = run_corpus(default_corpus(), [Exploding()])
    assert any("Exploding" in failure for failure in report.failures)


# --- phép đo ---


def test_precision_is_none_when_nothing_was_flagged():
    """Precision của một detector chưa từng kêu không phải 0% và cũng không
    phải 100% — nó là chưa biết."""
    assert ConfusionMatrix().precision is None
    assert ConfusionMatrix(false_negatives=5).precision is None


def test_recall_is_none_when_there_was_nothing_to_find():
    assert ConfusionMatrix(true_negatives=5).recall is None


def test_f1_needs_both_halves():
    assert ConfusionMatrix(false_negatives=3).f1 is None   # chưa từng kêu
    assert ConfusionMatrix(true_negatives=3).f1 is None    # chưa có gì đáng kêu
    matrix = ConfusionMatrix(true_positives=8, false_positives=2, false_negatives=2)
    assert 0.7 < matrix.f1 < 0.9


def test_a_perfect_score_on_one_sample_is_flagged_as_too_few():
    """Một mẫu đúng cho ra precision 1.0, recall 1.0, F1 1.0 — ba con số hoàn
    hảo và hoàn toàn vô nghĩa. `enough_samples` là thứ nói ra điều đó."""
    matrix = ConfusionMatrix(true_positives=1)
    assert matrix.precision == 1.0 and matrix.recall == 1.0 and matrix.f1 == 1.0
    assert matrix.to_dict()["enough_samples"] is False


def test_false_positives_per_host_day_is_the_number_people_live_with():
    """"Precision 92%" nghe ổn cho tới khi nó là 40 cảnh báo sai mỗi ngày."""
    assert false_positives_per_host_day(40, 1, 1) == 40.0
    assert false_positives_per_host_day(40, 20, 2) == 1.0
    assert false_positives_per_host_day(1, 0, 1) is None
    assert false_positives_per_host_day(1, 1, 0) is None


def test_calibration_error_catches_a_lying_confidence():
    """Nếu detector nói 0.9 mà đúng 60% thì con số 0.9 đang nói dối."""
    honest = expected_calibration_error([(0.9, 90, 100)])
    liar = expected_calibration_error([(0.9, 60, 100)])
    assert honest < 0.01
    assert liar > 0.25


def test_calibration_error_refuses_a_tiny_sample():
    assert expected_calibration_error([(0.9, 2, 3)]) is None


def test_merge_split_accuracy_notices_a_wrong_grouping():
    """Ghép hai sự việc không liên quan làm một, hay xé một sự việc thành năm,
    đều làm hỏng điều tra theo cách khó thấy: tổng số incident vẫn hợp lý."""
    expected = {"a": 1, "b": 1, "c": 2, "d": 2}
    assert merge_split_accuracy(expected, dict(expected)) == 1.0
    merged_everything = {"a": 1, "b": 1, "c": 1, "d": 1}
    assert merge_split_accuracy(expected, merged_everything) < 1.0
    split_everything = {"a": 1, "b": 2, "c": 3, "d": 4}
    assert merge_split_accuracy(expected, split_everything) < 1.0


def test_merge_accuracy_needs_at_least_two_items():
    assert merge_split_accuracy({"a": 1}, {"a": 1}) is None


def test_the_wilson_interval_matches_the_calibration_module():
    """Hai ngưỡng khác nhau cho cùng một khái niệm là hai câu trả lời khác nhau
    cho cùng một câu hỏi."""
    from shield.decision.calibration import MIN_SAMPLES as CAL_MIN

    assert MIN_SAMPLES == CAL_MIN
    assert wilson_interval(19, 19) is None or wilson_interval(19, 19)[0] < 1.0
    assert wilson_interval(5, 5) is None


# --- cổng ---


def test_the_gate_lists_what_failed_not_just_that_it_failed():
    """"Gate đỏ" không giúp ai sửa được gì; "detector X precision 0.41 trên 60
    mẫu" thì giúp."""
    report = MetricsReport()
    report.tool_policy_violations = 3
    report.total_claims, report.unsupported_claims = 10, 2
    problems = report.gate_failures()
    assert any("tool ngoài chính sách" in p for p in problems)
    assert any("không có căn cứ" in p for p in problems)
    for problem in problems:
        assert len(problem) > 15


def test_a_tool_policy_violation_always_fails_the_gate():
    """Mục 5 gate: tool-policy violation rate bằng 0 trong bộ gate bắt buộc."""
    report = MetricsReport()
    report.tool_policy_violations = 1
    assert report.gate_failures()


def test_not_enough_samples_is_reported_rather_than_passed_silently():
    report = run_corpus(default_corpus(), _detectors())
    problems = report.gate_failures(min_precision=0.9)
    assert any("chưa đủ mẫu" in p for p in problems), \
        "corpus nhỏ mà gate im lặng cho qua là gate vô dụng"
