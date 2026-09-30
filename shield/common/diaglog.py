"""Log chẩn đoán: định dạng ổn định, theo dõi khoá DB, chống lặp.

Mọi dòng "sự kiện vận hành" của agent theo dạng `tên_sự_kiện key=value key=value`
để `journalctl ... | grep`/`awk` lọc được và người đọc thấy ngay con số quan
trọng — thay vì một câu văn hoặc một `dict` in nguyên.

Ba thứ có ở đây vì đợt sự cố 30/09/2026 (agent bị watchdog kill lúc 17:32) phải
đo tay mới biết nguyên nhân:

- `TrackedRLock`: biết AI đang giữ khoá kết nối DB dùng chung, giữ bao lâu và
  đang chạy câu SQL nào. Ping watchdog phải chờ đúng khoá này.
- `kv()`: một cách duy nhất để ghi cặp key=value (có nháy khi cần).
- `RateLimiter`: cùng một cảnh báo lặp mỗi giây chỉ ghi một dòng kèm số lần bị nén.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass

LOG_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-7s %(name)s: %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format=LOG_FORMAT, datefmt=LOG_DATEFMT)


def _fmt(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".") if value != int(value) else str(int(value))
    text = str(value)
    if text == "" or any(ch in text for ch in " \t\n\"'="):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    return text


def kv(**fields: object) -> str:
    """`kv(rule="R", risk=82)` -> `rule=R risk=82`. Thứ tự khai báo được giữ."""
    return " ".join(f"{key}={_fmt(value)}" for key, value in fields.items() if value is not None)


def event(name: str, **fields: object) -> str:
    """`event("alert", rule="R")` -> `alert rule=R`: tên sự kiện đứng đầu, dễ grep."""
    body = kv(**fields)
    return f"{name} {body}" if body else name


@dataclass(frozen=True)
class LockSnapshot:
    held: bool
    thread: str
    held_for_s: float
    label: str


class TrackedRLock:
    """`threading.RLock` biết chủ hiện tại, thời gian giữ và nhãn việc đang làm.

    Chỉ theo dõi LẦN GIỮ NGOÀI CÙNG (đệ quy không tính). Thống kê `max_wait_s` /
    `max_hold_s` được đọc-và-xoá bởi `drain_stats()` — heartbeat dùng chúng.
    `on_slow_hold(snapshot)` được gọi khi nhả một lần giữ dài hơn `slow_hold_s`.
    """

    def __init__(self, slow_hold_s: float = 1.0, on_slow_hold=None) -> None:
        self._lock = threading.RLock()
        self._meta = threading.Lock()
        self.slow_hold_s = slow_hold_s
        self.on_slow_hold = on_slow_hold
        self._depth = 0
        self._owner = ""
        self._since = 0.0
        self._label = ""
        self._max_wait = 0.0
        self._max_hold = 0.0
        self._slow_holds = 0

    def label(self, text: str) -> None:
        """Ghi nhãn việc đang làm (vd. đầu câu SQL) — chỉ có nghĩa khi đang giữ khoá."""
        self._label = text

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        started = time.monotonic()
        ok = self._lock.acquire(blocking, timeout)
        if not ok:
            return False
        waited = time.monotonic() - started
        with self._meta:
            self._depth += 1
            if self._depth == 1:
                self._owner = threading.current_thread().name
                self._since = time.monotonic()
                self._label = ""
            if waited > self._max_wait:
                self._max_wait = waited
        return True

    def release(self) -> None:
        slow: LockSnapshot | None = None
        with self._meta:
            self._depth -= 1
            if self._depth == 0:
                held = time.monotonic() - self._since
                if held > self._max_hold:
                    self._max_hold = held
                if held >= self.slow_hold_s:
                    self._slow_holds += 1
                    slow = LockSnapshot(True, self._owner, held, self._label)
                self._owner, self._label = "", ""
        self._lock.release()
        if slow is not None and self.on_slow_hold is not None:
            try:
                self.on_slow_hold(slow)
            except Exception:  # noqa: BLE001 — log chẩn đoán không được làm hỏng thao tác DB
                pass

    def __enter__(self) -> "TrackedRLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def snapshot(self) -> LockSnapshot:
        """Ai đang giữ khoá, bao lâu, làm gì — an toàn gọi từ luồng bất kỳ."""
        with self._meta:
            if self._depth == 0:
                return LockSnapshot(False, "", 0.0, "")
            return LockSnapshot(True, self._owner, time.monotonic() - self._since, self._label)

    def drain_stats(self) -> dict:
        with self._meta:
            stats = {"max_wait_s": self._max_wait, "max_hold_s": self._max_hold,
                     "slow_holds": self._slow_holds}
            self._max_wait = self._max_hold = 0.0
            self._slow_holds = 0
            return stats


class RateLimiter:
    """Chỉ cho ghi một dòng mỗi `interval_s` cho mỗi khoá; đếm phần bị nén."""

    def __init__(self, interval_s: float = 600.0, clock=time.monotonic) -> None:
        self.interval_s = interval_s
        self._clock = clock
        self._last: dict[str, float] = {}
        self._suppressed: dict[str, int] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        """(được ghi không, số lần đã bị nén kể từ lần ghi trước)."""
        now_ts = self._clock()
        last = self._last.get(key)
        if last is not None and now_ts - last < self.interval_s:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return False, 0
        self._last[key] = now_ts
        return True, self._suppressed.pop(key, 0)


def process_rss_mb() -> float:
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def cgroup_memory_mb() -> tuple[float, float]:
    """(đang dùng, giới hạn) của cgroup hiện tại, MB; 0 nếu không đọc được / không giới hạn."""
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as handle:
            path = next((line.strip().split(":", 2)[2] for line in handle if line.startswith("0::")), "")
        base = f"/sys/fs/cgroup{path}"
        current = int(open(f"{base}/memory.current", encoding="utf-8").read().strip()) / 2**20
        raw = open(f"{base}/memory.max", encoding="utf-8").read().strip()
        return current, (0.0 if raw == "max" else int(raw) / 2**20)
    except (OSError, ValueError, StopIteration, IndexError):
        return 0.0, 0.0


def wal_size_mb(db_path: str) -> float:
    try:
        return os.path.getsize(db_path + "-wal") / 2**20
    except OSError:
        return 0.0
