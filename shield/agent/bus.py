"""Hàng đợi trung tâm: Collectors -> Event bus -> Detectors -> Alert bus -> {SQLite, IPC, Notifier}.

Xem KE-HOACH-SHIELD.md mục 1.1. Ở giai đoạn 0 chưa có detector thật, chỉ có
fake injector đẩy thẳng Alert vào alert_bus để verify đường ống đầu-cuối.
"""

from __future__ import annotations

import asyncio
from typing import Generic, TypeVar

T = TypeVar("T")


class Bus(Generic[T]):
    """Pub/sub đơn giản: mỗi subscriber có Queue riêng, publish fan-out cho tất cả."""

    def __init__(self, max_queue_size: int = 4096, overflow_policy: str = "block") -> None:
        if max_queue_size < 1:
            raise ValueError("max_queue_size must be positive")
        if overflow_policy not in {"block", "drop_oldest"}:
            raise ValueError("overflow_policy must be block or drop_oldest")
        self.max_queue_size = max_queue_size
        self.overflow_policy = overflow_policy
        self._subscribers: list[asyncio.Queue[T]] = []
        self.published = 0
        self.backpressure_count = 0
        self.dropped = 0

    def subscribe(self) -> "asyncio.Queue[T]":
        q: asyncio.Queue[T] = asyncio.Queue(maxsize=self.max_queue_size)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue[T]") -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def publish(self, item: T) -> None:
        for q in self._subscribers:
            if q.full():
                self.backpressure_count += 1
                if self.overflow_policy == "drop_oldest":
                    try:
                        q.get_nowait()
                        self.dropped += 1
                    except asyncio.QueueEmpty:
                        pass
            if self.overflow_policy == "drop_oldest":
                q.put_nowait(item)
            else:
                await q.put(item)
        self.published += 1

    def publish_nowait(self, item: T) -> None:
        """Đăng một item từ mã đồng bộ, không chờ.

        Dùng cho những chỗ phát hiện ra một sự việc trong lúc đang chạy đồng bộ
        (ví dụ: một response vừa thất bại kiểm chứng) và không thể `await`.
        Áp dụng đúng chính sách tràn như `publish`; với `drop_oldest` thì không
        bao giờ chặn, và với chính sách khác thì THÀ BỎ còn hơn chặn — một lời
        gọi đồng bộ chờ trên hàng đợi đầy sẽ treo cả tiến trình.
        """
        for q in self._subscribers:
            if q.full():
                self.backpressure_count += 1
                try:
                    q.get_nowait()
                    self.dropped += 1
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                self.dropped += 1
        self.published += 1

    def stats(self) -> dict[str, int]:
        return {
            "subscribers": len(self._subscribers), "published": self.published,
            "backpressure_count": self.backpressure_count,
            "dropped": self.dropped,
            "max_queue_depth": max((q.qsize() for q in self._subscribers), default=0),
            "capacity": self.max_queue_size,
        }
