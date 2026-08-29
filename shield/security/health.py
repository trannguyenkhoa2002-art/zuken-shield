"""Runtime health, bounded collector restart, and storage guardrails."""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

from shield.common.models import Alert, now


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class RetentionPolicy:
    event_days: int = 30
    alert_days: int = 90
    snapshot_days: int = 30
    pcap_days: int = 14
    database_max_bytes: int = 2 * 1024**3
    pcap_max_bytes: int = 5 * 1024**3
    disk_degraded_percent: int = 85
    disk_failed_percent: int = 95

    @classmethod
    def from_env(cls) -> "RetentionPolicy":
        return cls(
            event_days=_env_int("SHIELD_RETENTION_EVENT_DAYS", 30, 1, 3650),
            alert_days=_env_int("SHIELD_RETENTION_ALERT_DAYS", 90, 1, 3650),
            snapshot_days=_env_int("SHIELD_RETENTION_SNAPSHOT_DAYS", 30, 1, 3650),
            pcap_days=_env_int("SHIELD_RETENTION_PCAP_DAYS", 14, 1, 3650),
            database_max_bytes=_env_int("SHIELD_DATABASE_MAX_MB", 2048, 64, 1024 * 1024) * 1024**2,
            pcap_max_bytes=_env_int("SHIELD_PCAP_MAX_MB", 5120, 64, 1024 * 1024) * 1024**2,
            disk_degraded_percent=_env_int("SHIELD_DISK_DEGRADED_PERCENT", 85, 50, 99),
            disk_failed_percent=_env_int("SHIELD_DISK_FAILED_PERCENT", 95, 51, 100),
        )


def directory_size(root: Path, *, max_files: int = 100_000) -> int:
    if not root.exists() or root.is_symlink():
        return 0
    total = 0
    count = 0
    for base, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(base) / name).is_symlink()]
        for name in filenames:
            path = Path(base) / name
            try:
                if not path.is_symlink() and path.is_file():
                    total += path.stat().st_size
                    count += 1
            except OSError:
                continue
            if count >= max_files:
                return total
    return total


def prune_managed_files(
    root: Path, *, retention_days: int, maximum_bytes: int,
    suffixes: tuple[str, ...] = (".pcap", ".pcapng"),
) -> dict[str, int]:
    """Delete only regular managed files, oldest first; never follows symlinks."""
    if not root.exists() or root.is_symlink():
        return {"deleted": 0, "freed_bytes": 0, "remaining_bytes": 0}
    resolved_root = root.resolve()
    files: list[tuple[float, int, Path]] = []
    for path in root.iterdir():
        try:
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            resolved = path.resolve()
            if resolved.parent != resolved_root:
                continue
            stat = path.stat()
            files.append((stat.st_mtime, stat.st_size, path))
        except OSError:
            continue
    cutoff = time.time() - max(1, retention_days) * 86400
    total = sum(item[1] for item in files)
    deleted = freed = 0
    for mtime, size, path in sorted(files):
        if mtime >= cutoff and total <= maximum_bytes:
            continue
        try:
            path.unlink()
        except OSError:
            continue
        total -= size
        freed += size
        deleted += 1
    return {"deleted": deleted, "freed_bytes": freed, "remaining_bytes": max(0, total)}


class RuntimeMonitor:
    def __init__(self) -> None:
        self.started_ts = time.time()
        # Uptime là một KHOẢNG trong tiến trình -> đồng hồ đơn điệu. Đồng hồ
        # tường nhảy lùi lúc boot từng cho ra uptime âm.
        self._started_monotonic = time.monotonic()
        self._last_wall = time.monotonic()
        process_times = os.times()
        self._last_cpu = process_times.user + process_times.system
        self._last_events = 0

    @staticmethod
    def _rss_bytes() -> int:
        try:
            for line in Path("/proc/self/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
        return 0

    def sample(self, store, event_bus, alert_bus, pcap_dir: Path) -> dict[str, dict]:
        wall = time.monotonic()
        process_times = os.times()
        cpu = process_times.user + process_times.system
        elapsed = max(0.001, wall - self._last_wall)
        cpu_percent = max(0.0, 100.0 * (cpu - self._last_cpu) / elapsed)
        self._last_wall, self._last_cpu = wall, cpu

        stats = store.database_stats()
        disk = shutil.disk_usage(store.path.parent)
        disk_percent = 100.0 * (disk.total - disk.free) / max(1, disk.total)
        policy = RetentionPolicy.from_env()
        rss_bytes = self._rss_bytes()
        pcap_bytes = directory_size(pcap_dir)
        event_stats = event_bus.stats()
        alert_stats = alert_bus.stats()
        event_rate = max(0.0, (event_stats["published"] - self._last_events) / elapsed)
        self._last_events = event_stats["published"]
        values = {
            "cpu_percent": (cpu_percent, "%", "degraded" if cpu_percent >= 85 else "healthy", "agent process"),
            "memory_rss": (rss_bytes, "bytes", "degraded" if rss_bytes >= 768 * 1024**2 else "healthy", "resident memory"),
            "database_size": (stats["database_bytes"] + stats["wal_bytes"], "bytes", "degraded" if stats["database_bytes"] >= policy.database_max_bytes else "healthy", f"schema v{stats['schema_version']}"),
            "pcap_usage": (pcap_bytes, "bytes", "degraded" if pcap_bytes >= policy.pcap_max_bytes else "healthy", str(pcap_dir)),
            "disk_usage": (disk_percent, "%", "failed" if disk_percent >= policy.disk_failed_percent else "degraded" if disk_percent >= policy.disk_degraded_percent else "healthy", str(store.path.parent)),
            "agent_uptime": (time.monotonic() - self._started_monotonic, "seconds", "healthy", "current agent process"),
            "event_throughput": (event_rate, "events/s", "healthy", "normalized event bus"),
            "event_queue_depth": (event_stats["max_queue_depth"], "events", "degraded" if event_stats["max_queue_depth"] >= int(event_bus.max_queue_size * 0.8) else "healthy", f"capacity {event_bus.max_queue_size}"),
            "alert_queue_depth": (alert_stats["max_queue_depth"], "alerts", "degraded" if alert_stats["max_queue_depth"] >= int(alert_bus.max_queue_size * 0.8) else "healthy", f"capacity {alert_bus.max_queue_size}"),
            "dropped_events": (event_stats.get("dropped", 0), "events", "degraded" if event_stats.get("dropped", 0) else "healthy", "bounded queue guardrail"),
        }
        for metric, (value, unit, state, detail) in values.items():
            store.set_system_health(metric, value, unit, state, detail)

        # BUS THÀNH MỘT DÒNG SỨC KHOẺ RIÊNG.
        #
        # `Bus.stats()` vốn đã đếm `backpressure_count` và `dropped`, nhưng
        # chúng chưa bao giờ rời khỏi bộ nhớ tiến trình: `system_health` chỉ
        # lấy độ sâu hàng đợi và số bỏ của event bus, còn số bỏ của alert bus
        # và toàn bộ số lần chạm trần thì không ai thấy.
        #
        # Hai bus dùng chính sách `drop_oldest`, nghĩa là khi đầy chúng VỨT
        # event cũ đi và chạy tiếp. Đó là lựa chọn đúng — chặn cả đường ống còn
        # tệ hơn — nhưng nó chỉ đúng khi việc vứt NHÌN THẤY ĐƯỢC. Một Shield
        # đang mất event trông y hệt một Shield đang rảnh.
        for name, stats, bus in (("event_bus", event_stats, event_bus),
                                 ("alert_bus", alert_stats, alert_bus)):
            dropped = int(stats.get("dropped", 0))
            backpressure = int(stats.get("backpressure_count", 0))
            depth, capacity = stats["max_queue_depth"], stats["capacity"]
            detail = (f"{depth}/{capacity} trong hàng đợi, "
                      f"{stats['published']} đã phát, "
                      f"chính sách {bus.overflow_policy}")
            if backpressure:
                detail += f", {backpressure} lần chạm trần"
            if dropped:
                detail += f", ĐÃ BỎ {dropped}"
            store.set_collector_health(
                name, "asyncio-queue", not dropped, detail,
                state="degraded" if dropped else "running",
                dropped_events=dropped,
                error_message=f"{dropped} event bị bỏ do hàng đợi đầy" if dropped else "",
            )
        return {
            metric: {"value": value, "unit": unit, "state": state, "detail": detail}
            for metric, (value, unit, state, detail) in values.items()
        }


# Trọng số cho điểm sức khoẻ tổng. Collector chết nặng hơn đĩa đầy 86%: một
# collector không chạy nghĩa là Shield MÙ ở mảng đó, còn đĩa gần đầy chỉ là
# cảnh báo sớm. Trọng số để lộ ra đây, không chôn trong hàm, để người dùng
# đối chiếu được vì sao điểm bị trừ.
HEALTH_WEIGHTS = {
    "collector_failed": 25,
    "collector_degraded": 8,
    "metric_failed": 15,
    "metric_degraded": 5,
}

# Thành phần dùng CHUNG bảng `collector_health` nhưng KHÔNG thu telemetry.
# Chúng không trừ điểm sức khoẻ, và lý do rất cụ thể: điểm này trả lời "Shield
# có đang giám sát đầy đủ không". Một worker model sập không làm Shield mù một
# mảng nào — detection chạy y nguyên, và Phase 3B/3C-0 đã có phương án tất
# định thay thế. Trừ 25 điểm cho nó là nói với người dùng rằng mạng của họ
# đang hở, trong khi không hề.
#
# Vẫn HIỂN THỊ trong bảng sức khoẻ, chỉ không trừ điểm: giấu đi thì một worker
# hỏng liên tục sẽ không ai thấy.
NON_TELEMETRY_COMPONENTS = frozenset({"ai_model_worker"})


def overall_health(collector_health: list[dict], system_health: list[dict]) -> dict:
    """Một con số 0..100 cho sức khoẻ của SHIELD (mục B6 kế hoạch 1.1).

    Đây KHÔNG phải "mạng của bạn an toàn bao nhiêu phần trăm". Nó chỉ trả lời
    "Shield có đang hoạt động đầy đủ không" — cùng lý do `attack_coverage()`
    ghi rõ nó đo kỹ thuật đã quan sát, không phải mức độ an toàn. Nhầm hai
    thứ này là cách nhanh nhất để một dashboard xanh ru ngủ người dùng.
    """
    penalties: list[dict] = []
    score = 100

    for item in collector_health or []:
        if item.get("component") in NON_TELEMETRY_COMPONENTS:
            continue
        state = item.get("state") or ("healthy" if item.get("healthy") else "failed")
        if state == "failed":
            weight = HEALTH_WEIGHTS["collector_failed"]
        elif state == "degraded":
            weight = HEALTH_WEIGHTS["collector_degraded"]
        else:
            continue
        score -= weight
        penalties.append({
            "kind": "collector", "name": item.get("component", "?"),
            "state": state, "points": weight,
            "detail": item.get("error_message") or item.get("detail", ""),
        })

    for item in system_health or []:
        state = item.get("state", "healthy")
        if state == "failed":
            weight = HEALTH_WEIGHTS["metric_failed"]
        elif state == "degraded":
            weight = HEALTH_WEIGHTS["metric_degraded"]
        else:
            continue
        score -= weight
        penalties.append({
            "kind": "metric", "name": item.get("metric", "?"),
            "state": state, "points": weight, "detail": item.get("detail", ""),
        })

    score = max(0, min(100, score))
    if score >= 90:
        label = "healthy"
    elif score >= 60:
        label = "degraded"
    else:
        label = "failed"
    return {
        "score": score,
        "state": label,
        # Sắp theo mức trừ điểm: người dùng cần biết sửa cái gì TRƯỚC.
        "penalties": sorted(penalties, key=lambda item: -item["points"]),
        "components_checked": len(collector_health or []) + len(system_health or []),
    }


class CollectorSupervisor:
    """Restart a failed collector with a bounded crash window and health record."""

    def __init__(
        self, store, alert_bus, *, max_crashes: int = 5, crash_window_s: float = 600,
        heartbeat_s: float = 30, restart_backoff_s: float = 1,
    ) -> None:
        self.store = store
        self.alert_bus = alert_bus
        self.max_crashes = max(1, max_crashes)
        self.crash_window_s = max(1.0, crash_window_s)
        self.heartbeat_s = max(1.0, heartbeat_s)
        self.restart_backoff_s = max(0.0, restart_backoff_s)

    async def run(
        self, name: str, backend: str, factory: Callable[[], Awaitable[None]],
    ) -> None:
        crashes: deque[float] = deque()
        restart_count = 0
        started_ts = time.time()
        while True:
            self.store.set_collector_health(
                name, backend, True, "collector running", state="running",
                started_ts=started_ts, last_heartbeat=time.time(), restart_count=restart_count,
            )
            task = asyncio.create_task(factory(), name=f"shield-collector-{name}")
            try:
                while not task.done():
                    done, _pending = await asyncio.wait({task}, timeout=self.heartbeat_s)
                    if not done:
                        self.store.set_collector_health(
                            name, backend, True, "collector running", state="running",
                            started_ts=started_ts, last_heartbeat=time.time(), restart_count=restart_count,
                        )
                exception = task.exception()
                if exception is None:
                    raise RuntimeError("collector exited unexpectedly")
                raise exception
            except asyncio.CancelledError:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                self.store.set_collector_health(
                    name, backend, False, "collector stopped", state="stopped",
                    started_ts=started_ts, restart_count=restart_count,
                )
                raise
            except Exception as exc:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                timestamp = time.monotonic()
                crashes.append(timestamp)
                while crashes and timestamp - crashes[0] > self.crash_window_s:
                    crashes.popleft()
                restart_count += 1
                failed = len(crashes) >= self.max_crashes
                state = "failed" if failed else "degraded"
                detail = (
                    f"restart threshold reached ({len(crashes)}/{self.max_crashes})"
                    if failed else f"collector crashed; restart {restart_count} scheduled"
                )
                self.store.set_collector_health(
                    name, backend, False, detail, state=state, started_ts=started_ts,
                    last_heartbeat=time.time(), restart_count=restart_count,
                    error_message=f"{type(exc).__name__}: {exc}"[:1000],
                )
                if failed:
                    await self.alert_bus.publish(Alert(
                        now(), "SHIELD_COLLECTOR_FAILED", "critical",
                        "Shield collector stopped after repeated crashes",
                        f"{name} crashed {len(crashes)} times within {self.crash_window_s:.0f} seconds",
                        name,
                        evidence={"collector": name, "backend": backend, "restart_count": restart_count,
                                  "error": f"{type(exc).__name__}: {exc}", "derived": True},
                        playbook=["snapshot_state"],
                    ))
                    return
                await asyncio.sleep(min(30.0, self.restart_backoff_s * (2 ** min(restart_count, 5))))
