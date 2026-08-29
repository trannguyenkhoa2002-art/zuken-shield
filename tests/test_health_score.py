"""Điểm sức khoẻ tổng (mục B6 kế hoạch 1.1)."""

from __future__ import annotations

from shield.security.health import HEALTH_WEIGHTS, overall_health


def test_a_fully_working_shield_scores_one_hundred():
    result = overall_health(
        [{"component": "arp_sniffer", "state": "running", "healthy": 1}],
        [{"metric": "cpu_percent", "state": "healthy"}],
    )
    assert result["score"] == 100 and result["state"] == "healthy"
    assert result["penalties"] == []


def test_a_dead_collector_costs_more_than_a_nearly_full_disk():
    """Collector chết nghĩa là Shield MÙ ở mảng đó. Đĩa 86% chỉ là cảnh báo sớm."""
    collector_down = overall_health([{"component": "arp_sniffer", "state": "failed"}], [])
    disk_warning = overall_health([], [{"metric": "disk_usage", "state": "degraded"}])
    assert collector_down["score"] < disk_warning["score"]
    assert HEALTH_WEIGHTS["collector_failed"] > HEALTH_WEIGHTS["metric_degraded"]


def test_the_score_says_what_to_fix_first():
    result = overall_health(
        [{"component": "journal", "state": "degraded"},
         {"component": "arp_sniffer", "state": "failed", "detail": "scapy thiếu"}],
        [{"metric": "disk_usage", "state": "failed"}],
    )
    assert result["penalties"][0]["name"] == "arp_sniffer"
    assert result["penalties"][0]["detail"] == "scapy thiếu"


def test_the_score_never_leaves_zero_to_hundred():
    broken = [{"component": f"c{i}", "state": "failed"} for i in range(50)]
    assert overall_health(broken, [])["score"] == 0
    assert overall_health([], [])["score"] == 100


def test_state_labels_track_the_score():
    assert overall_health([{"component": "a", "state": "degraded"}], [])["state"] == "healthy"
    # 1 collector chết = 75 điểm -> degraded; 2 cái = 50 -> failed.
    assert overall_health([{"component": "a", "state": "failed"}], [])["state"] == "degraded"
    assert overall_health([{"component": "a", "state": "failed"},
                           {"component": "b", "state": "failed"}], [])["state"] == "failed"


def test_a_collector_without_an_explicit_state_falls_back_to_the_healthy_flag():
    """Bản ghi từ Shield cũ chưa có cột `state` — không được tính là hỏng."""
    assert overall_health([{"component": "a", "healthy": 1}], [])["score"] == 100
    assert overall_health([{"component": "a", "healthy": 0}], [])["score"] < 100


def test_empty_input_is_not_reported_as_perfect_health_without_saying_so():
    """Không có thành phần nào để kiểm thì điểm 100 là vô nghĩa — con số
    components_checked buộc UI phải nói ra điều đó."""
    assert overall_health([], [])["components_checked"] == 0
