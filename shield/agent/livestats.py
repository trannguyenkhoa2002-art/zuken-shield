"""Số liệu SỐNG: cái gì đang chạy ngay lúc này, đo thật, đẩy mỗi giây.

Trước đây bảng điều khiển chỉ vẽ lại khi có alert. Mạng bình thường cả ngày mới
có vài alert, nên màn hình đứng yên hàng giờ trong khi agent vẫn xử lý vài event
mỗi giây — hoạt động thật rất nhiều, chỉ là vô hình.

Ba ràng buộc định hình module này:

1. **Đếm trong bộ nhớ, không đếm bằng SQL.** Bảng `events` đã gần 800 nghìn
   dòng; chạy `count(*)` mỗi giây là tự đốt CPU và I/O của chính máy đang cần
   được bảo vệ.
2. **Gộp trước khi gửi.** Bây giờ khoảng 6 event/giây, nhưng lúc bị quét cổng có
   thể hàng nghìn. Đẩy từng cái một sẽ nghẽn socket IPC và đơ giao diện. Ở đây
   gộp thành thùng một giây, và dòng sự kiện chạy có trần cứng mỗi lượt.
3. **Số phải thật.** Không nội suy, không làm mượt cho đẹp. Một bảng điều khiển
   bịa số tệ hơn một bảng đứng yên, vì nó khiến người ta tin vào cái không có.
"""

from __future__ import annotations

import time
from collections import deque

# Cửa sổ tính tốc độ. 60 giây vừa đủ mượt để đọc, vừa đủ ngắn để một đợt quét
# cổng nhìn thấy được ngay chứ không bị trung bình hoá mất.
RATE_WINDOW_S = 60
# Trần số dòng sự kiện gửi kèm mỗi lượt. Vượt trần thì gửi kèm số bị bỏ, chứ
# không im lặng cắt bớt — "có 900 dòng nữa" là thông tin, giấu đi là nói dối.
FEED_PER_TICK = 25
# Collector im lặng bao lâu thì đáng ngờ (dùng cho problems.py).
SOURCE_IDLE_S = 600


class LiveStats:
    """Bộ đếm trong tiến trình. `record()` gọi từ vòng tiêu thụ event."""

    def __init__(self, clock=time.time) -> None:
        self._clock = clock
        self._buckets: deque[tuple[int, int]] = deque()   # (giây, số event)
        self._per_source: dict[str, dict] = {}
        self._feed: deque[dict] = deque(maxlen=FEED_PER_TICK * 8)
        self._feed_dropped = 0
        self.total_events = 0
        self.started_ts = clock()

    # --- ghi nhận ---------------------------------------------------------
    def record(self, event) -> None:
        at = self._clock()
        second = int(at)
        if self._buckets and self._buckets[-1][0] == second:
            self._buckets[-1] = (second, self._buckets[-1][1] + 1)
        else:
            self._buckets.append((second, 1))
        self._trim(at)
        self.total_events += 1

        source = str(getattr(event, "source", "unknown"))
        entry = self._per_source.setdefault(
            source, {"count": 0, "last_ts": 0.0, "recent": deque()}
        )
        entry["count"] += 1
        entry["last_ts"] = at
        entry["recent"].append(second)
        while entry["recent"] and entry["recent"][0] < second - RATE_WINDOW_S:
            entry["recent"].popleft()

        if len(self._feed) == self._feed.maxlen:
            self._feed_dropped += 1
        self._feed.append({
            "ts": getattr(event, "ts", at),
            "source": source,
            "kind": str(getattr(event, "kind", "")),
            "origin": str((getattr(event, "data", {}) or {}).get("origin", "local")),
        })

    def _trim(self, at: float) -> None:
        cutoff = int(at) - RATE_WINDOW_S
        while self._buckets and self._buckets[0][0] < cutoff:
            self._buckets.popleft()

    # --- đọc ra -----------------------------------------------------------
    def rate(self, seconds: int = 5) -> float:
        """Event/giây trung bình trong `seconds` giây vừa qua."""
        at = self._clock()
        self._trim(at)
        cutoff = int(at) - max(1, seconds)
        total = sum(count for second, count in self._buckets if second > cutoff)
        return total / max(1, seconds)

    def series(self, seconds: int = RATE_WINDOW_S) -> list[int]:
        """Số event từng giây, đủ `seconds` điểm, mới nhất ở cuối.

        Trả về đủ độ dài kể cả khi chưa có dữ liệu: đồ thị co giãn theo số điểm
        đang có sẽ nhìn như dữ liệu đang nhảy loạn trong khi thực ra chỉ là trục
        đang đổi.
        """
        at = int(self._clock())
        counts = dict(self._buckets)
        return [counts.get(at - offset, 0) for offset in range(seconds - 1, -1, -1)]

    def sources(self) -> list[dict]:
        """Tốc độ theo từng collector — thấy được cái nào đang làm việc.

        Trạng thái `running` không nói lên điều gì: một collector còn sống mà
        không sinh event nào suốt mười phút trông y hệt một mạng yên tĩnh.
        """
        at = self._clock()
        second = int(at)
        rows = []
        for source, entry in sorted(self._per_source.items()):
            recent = [item for item in entry["recent"] if item >= second - RATE_WINDOW_S]
            rows.append({
                "source": source,
                "total": entry["count"],
                "per_minute": len(recent),
                "last_ts": entry["last_ts"],
                "idle_s": at - entry["last_ts"] if entry["last_ts"] else 0.0,
            })
        return rows

    def drain_feed(self, limit: int = FEED_PER_TICK) -> tuple[list[dict], int]:
        """Lấy các dòng chưa gửi. Trả (dòng, số đã bỏ vì quá nhanh)."""
        taken = []
        while self._feed and len(taken) < limit:
            taken.append(self._feed.popleft())
        dropped = self._feed_dropped + len(self._feed)
        self._feed.clear()
        self._feed_dropped = 0
        return taken, dropped

    def snapshot(self, paused: bool = False) -> dict:
        feed, dropped = self.drain_feed()
        return {
            "ts": self._clock(),
            "paused": bool(paused),
            "events_per_s": round(self.rate(5), 2),
            "events_per_s_1m": round(self.rate(RATE_WINDOW_S), 2),
            "events_total": self.total_events,
            "uptime_s": self._clock() - self.started_ts,
            "series": self.series(),
            "sources": self.sources(),
            "feed": feed,
            "feed_dropped": dropped,
        }


def idle_sources(sources: list[dict], idle_s: float = SOURCE_IDLE_S) -> list[dict]:
    """Collector đã từng sinh event nhưng im lặng quá lâu.

    Chỉ xét cái đã từng chạy: một collector chưa bao giờ sinh event có thể chỉ
    là chưa có gì để báo, không phải hỏng.
    """
    return [row for row in sources
            if row.get("total", 0) > 0 and row.get("idle_s", 0.0) > idle_s]
