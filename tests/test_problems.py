"""Shield tự báo khi CHÍNH NÓ gặp vấn đề — bằng tiếng Anh, kèm việc cần làm."""

from __future__ import annotations

import time

from shield.agent.problems import (
    PROBE_SILENT_S,
    STARTUP_GRACE_S,
    SYSLOG_DROP_THRESHOLD,
    ProblemReporter,
    component_is_enabled,
    detect_problems,
    problem_to_alert,
    resolved_message,
)

NOW = 1_700_000_000.0


def test_a_failed_collector_is_reported():
    problems = detect_problems(collector_health=[
        {"component": "dns", "state": "failed", "healthy": False, "error_message": "no socket"},
    ], now_ts=NOW)
    assert len(problems) == 1
    assert problems[0].severity == "critical"
    assert "dns" in problems[0].title
    assert "unmonitored" in problems[0].detail


def test_a_healthy_collector_is_not_reported():
    assert detect_problems(collector_health=[
        {"component": "dns", "state": "running", "healthy": True,
         "backend": "udp", "detail": "listening"},
    ], now_ts=NOW) == []


def test_an_optional_feature_that_was_never_enabled_is_not_an_alarm():
    """`signed_configuration` báo healthy=False khi chưa cấu hình chữ ký.

    Đó là tính năng tuỳ chọn chưa bật, không phải hỏng. Báo động cho thứ chưa
    bao giờ chạy là cách nhanh nhất dạy người dùng rằng cảnh báo của Shield
    không đáng đọc — và khi đó cái thật sự quan trọng cũng không tới được ai.
    """
    rows = [
        {"component": "signed_configuration", "backend": "development", "healthy": False,
         "detail": "signature enforcement not configured", "state": "running"},
        {"component": "log_ingest", "backend": "disabled", "healthy": True,
         "detail": "chưa cấu hình probe", "state": "running"},
    ]
    assert detect_problems(collector_health=rows, now_ts=NOW) == []
    assert not component_is_enabled(rows[0])
    assert not component_is_enabled(rows[1])
    assert component_is_enabled({"component": "dns", "backend": "udp", "detail": "listening"})


def test_a_real_failure_is_still_reported_among_disabled_ones():
    rows = [
        {"component": "log_ingest", "backend": "disabled", "healthy": True, "detail": "chưa cấu hình"},
        {"component": "dns", "backend": "udp", "healthy": False, "detail": "socket lỗi",
         "state": "failed"},
    ]
    found = detect_problems(collector_health=rows, now_ts=NOW)
    assert [item.problem_id for item in found] == ["collector_failed:dns"]


def test_idle_sources_are_not_reported_during_startup():
    """Ngay sau khởi động thì mọi nguồn đều "chưa sinh event"."""
    idle = [{"source": "arp", "idle_s": 900, "total": 500}]
    assert detect_problems(idle_collectors=idle, agent_uptime_s=60, now_ts=NOW) == []
    found = detect_problems(idle_collectors=idle,
                            agent_uptime_s=STARTUP_GRACE_S + 1, now_ts=NOW)
    assert [item.problem_id for item in found] == ["source_idle:arp"]


def test_a_silent_probe_is_reported():
    problems = detect_problems(probe_health=[
        {"probe_id": "p1", "display_name": "web-server", "last_seen": NOW - PROBE_SILENT_S - 60},
    ], now_ts=NOW)
    assert problems[0].severity == "critical"
    assert "web-server" in problems[0].title
    # Probe im lặng giữa lúc có sự cố tự nó là một dấu hiệu.
    assert "itself a finding" in problems[0].remedy


def test_kernel_drops_are_only_reported_when_they_grow():
    stats = {"kernel_dropped": 500}
    # Lần đầu thấy 500 gói đã mất -> báo.
    assert detect_problems(syslog_stats=stats, previous_syslog_drops=0, now_ts=NOW)
    # Không tăng thêm -> không báo lại.
    assert detect_problems(syslog_stats=stats, previous_syslog_drops=500, now_ts=NOW) == []
    # Tăng nhưng dưới ngưỡng -> không báo.
    assert detect_problems(
        syslog_stats={"kernel_dropped": 500 + SYSLOG_DROP_THRESHOLD - 1},
        previous_syslog_drops=500, now_ts=NOW,
    ) == []


def test_an_unreadable_drop_counter_is_not_treated_as_zero_loss():
    """`-1` nghĩa là không đọc được bộ đếm, không phải "không mất gói nào"."""
    assert detect_problems(
        syslog_stats={"kernel_dropped": -1}, previous_syslog_drops=0, now_ts=NOW,
    ) == []


def test_database_recovery_is_reported_with_what_was_lost():
    problems = detect_problems(recovery={
        "rows_recovered": 640445, "rows_lost": 1458,
        "quarantined_path": "/var/lib/shield/shield.db.corrupt.123",
    }, now_ts=NOW)
    assert len(problems) == 1
    assert "640445" in problems[0].detail and "1458" in problems[0].detail
    # Hỏng database thường là đĩa hỏng, nhưng cũng có thể là dấu vết tấn công.
    assert "smartctl" in problems[0].remedy


def test_every_problem_says_what_to_do():
    """Thông báo nói "có vấn đề" mà không nói làm gì thì lần thứ ba sẽ bị tắt."""
    problems = detect_problems(
        collector_health=[{"component": "a", "state": "failed", "healthy": False}],
        probe_health=[{"probe_id": "p", "last_seen": NOW - PROBE_SILENT_S - 1, "dropped": 5}],
        syslog_stats={"kernel_dropped": 9999},
        recovery={"rows_recovered": 1, "rows_lost": 0, "quarantined_path": "/x"},
        now_ts=NOW,
    )
    assert len(problems) >= 5
    for problem in problems:
        assert problem.remedy.strip(), f"{problem.problem_id} không nói phải làm gì"
        assert problem.message().startswith(problem.detail)
        assert "What to do:" in problem.message()


def test_messages_are_english():
    """Nội dung rời khỏi máy phải là tiếng Anh — có thể tới tay người trực khác."""
    problems = detect_problems(
        collector_health=[{"component": "dns", "state": "failed", "healthy": False}],
        now_ts=NOW,
    )
    text = problems[0].title + problems[0].detail + problems[0].remedy
    assert not any(ord(character) > 127 for character in text), text


def test_the_same_problem_is_not_reported_twice():
    """Gửi lại cùng một thông báo mỗi phút là cách nhanh nhất để bị tắt đi."""
    reporter = ProblemReporter()
    problems = detect_problems(
        collector_health=[{"component": "dns", "state": "failed", "healthy": False}],
        now_ts=NOW,
    )
    opened, resolved = reporter.sync(problems)
    assert len(opened) == 1 and resolved == []
    opened, resolved = reporter.sync(problems)
    assert opened == [] and resolved == []


def test_recovery_is_announced_when_a_problem_clears():
    """Thông báo chỉ biết kêu mà không bao giờ nói "đã ổn" thì lần sau không ai đọc."""
    reporter = ProblemReporter()
    problems = detect_problems(
        collector_health=[{"component": "dns", "state": "failed", "healthy": False}],
        now_ts=NOW,
    )
    reporter.sync(problems)
    opened, resolved = reporter.sync([])
    assert opened == []
    assert len(resolved) == 1
    assert "Resolved:" in resolved_message(resolved[0])


def test_a_problem_alert_is_always_notified_even_at_warning_level():
    """Collector im lặng không phải `critical` nhưng vẫn phải tới người dùng."""
    problems = detect_problems(
        idle_collectors=[{"source": "arp", "idle_s": 900, "total": 500}],
        agent_uptime_s=STARTUP_GRACE_S + 1, now_ts=NOW)
    alert = problem_to_alert(problems[0])
    assert alert.severity == "warning"
    assert alert.evidence["notify_always"] is True
    assert alert.evidence["remedy"]


def test_detect_problems_needs_no_running_agent():
    """Hàm thuần, nhận dict — kiểm thử được mà không cần agent sống."""
    assert detect_problems() == []
    assert detect_problems(collector_health=[], probe_health=[], syslog_stats={}) == []


def test_current_time_is_used_when_not_given():
    problems = detect_problems(probe_health=[
        {"probe_id": "p1", "last_seen": time.time() - PROBE_SILENT_S - 60},
    ])
    assert problems and problems[0].problem_id == "probe_silent:p1"
