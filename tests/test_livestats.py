"""Số liệu sống: phải là số ĐẾM THẬT, và không được làm nghẽn đường truyền."""

from __future__ import annotations

from shield.agent.livestats import (
    FEED_PER_TICK,
    RATE_WINDOW_S,
    LiveStats,
    idle_sources,
)
from shield.common.models import Event


class Clock:
    def __init__(self, at: float = 1000.0) -> None:
        self.at = at

    def __call__(self) -> float:
        return self.at

    def advance(self, seconds: float) -> None:
        self.at += seconds


def event(clock: Clock, source: str = "arp", kind: str = "seen", origin: str = "local") -> Event:
    return Event(clock.at, source, kind, {"origin": origin})


def test_rate_counts_only_the_recent_window():
    clock = Clock()
    stats = LiveStats(clock=clock)
    for _ in range(10):
        stats.record(event(clock))
    assert stats.rate(seconds=5) == 2.0        # 10 event / 5 giây
    clock.advance(30)
    assert stats.rate(seconds=5) == 0.0        # đã trôi khỏi cửa sổ


def test_the_total_never_forgets():
    clock = Clock()
    stats = LiveStats(clock=clock)
    for _ in range(5):
        stats.record(event(clock))
    clock.advance(3600)
    assert stats.rate(seconds=5) == 0.0
    assert stats.total_events == 5


def test_the_series_always_has_a_fixed_length():
    """Đồ thị co giãn theo số điểm đang có sẽ nhìn như dữ liệu nhảy loạn."""
    clock = Clock()
    stats = LiveStats(clock=clock)
    assert len(stats.series()) == RATE_WINDOW_S
    stats.record(event(clock))
    assert len(stats.series()) == RATE_WINDOW_S
    assert stats.series()[-1] == 1


def test_each_source_is_counted_separately():
    clock = Clock()
    stats = LiveStats(clock=clock)
    for _ in range(7):
        stats.record(event(clock, source="arp"))
    for _ in range(3):
        stats.record(event(clock, source="dns"))
    rows = {row["source"]: row for row in stats.sources()}
    assert rows["arp"]["per_minute"] == 7
    assert rows["dns"]["per_minute"] == 3
    assert rows["arp"]["idle_s"] == 0.0


def test_a_source_that_goes_quiet_is_visible():
    """Collector còn sống mà im lặng trông y hệt một mạng yên tĩnh."""
    clock = Clock()
    stats = LiveStats(clock=clock)
    stats.record(event(clock, source="arp"))
    clock.advance(900)
    stats.record(event(clock, source="dns"))
    rows = {row["source"]: row for row in stats.sources()}
    assert rows["arp"]["per_minute"] == 0
    assert rows["arp"]["idle_s"] == 900
    assert [row["source"] for row in idle_sources(stats.sources(), idle_s=600)] == ["arp"]


def test_a_source_that_never_produced_anything_is_not_called_idle():
    """Chưa bao giờ sinh event có thể chỉ là chưa có gì để báo."""
    assert idle_sources([{"source": "x", "total": 0, "idle_s": 9999}]) == []


def test_the_feed_is_capped_per_tick():
    """Một đợt quét cổng sinh hàng nghìn event/giây — đẩy hết sẽ nghẽn IPC."""
    clock = Clock()
    stats = LiveStats(clock=clock)
    for _ in range(1000):
        stats.record(event(clock))
    feed, dropped = stats.drain_feed()
    assert len(feed) == FEED_PER_TICK
    assert dropped > 0, "bỏ bớt mà không đếm là cắt trong im lặng"


def test_draining_the_feed_twice_does_not_repeat_lines():
    clock = Clock()
    stats = LiveStats(clock=clock)
    for _ in range(5):
        stats.record(event(clock))
    first, _ = stats.drain_feed()
    second, _ = stats.drain_feed()
    assert len(first) == 5
    assert second == []


def test_the_feed_marks_where_a_log_came_from():
    """Log từ máy khác phải nhìn ra ngay là từ máy khác."""
    clock = Clock()
    stats = LiveStats(clock=clock)
    stats.record(event(clock, source="probe.file", origin="probe:web-01"))
    feed, _ = stats.drain_feed()
    assert feed[0]["origin"] == "probe:web-01"


def test_the_snapshot_carries_everything_the_dashboard_needs():
    clock = Clock()
    stats = LiveStats(clock=clock)
    stats.record(event(clock))
    snapshot = stats.snapshot()
    for key in ("events_per_s", "events_total", "series", "sources", "feed",
                "feed_dropped", "uptime_s", "paused"):
        assert key in snapshot, key
    assert snapshot["paused"] is False
    assert snapshot["events_total"] == 1


def test_a_paused_snapshot_says_so():
    """Số vẫn nhảy sau khi bấm dừng sẽ khiến người dùng không tin cái nút đó."""
    stats = LiveStats(clock=Clock())
    assert stats.snapshot(paused=True)["paused"] is True


def test_counting_never_touches_the_database():
    """Bảng events đã gần 800 nghìn dòng — đếm bằng SQL mỗi giây là tự đốt máy."""
    import inspect

    from shield.agent import livestats

    source = inspect.getsource(livestats)
    for forbidden in ("sqlite3", "SELECT", "store."):
        assert forbidden not in source, f"livestats không được chạm database ({forbidden})"
