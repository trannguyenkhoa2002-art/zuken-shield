"""Log chẩn đoán: đủ chi tiết để dựng lại một sự cố mà không phải đo lại bằng tay.

Sự cố 30/09/2026: agent bị watchdog kill; log không nói ai giữ khoá DB, lượt
bảo trì tốn bao lâu ở bước nào, hay tình trạng trước đó ra sao.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time

from shield.agent import __main__ as agent
from shield.agent.bus import Bus
from shield.agent.store import Store
from shield.common.diaglog import RateLimiter, TrackedRLock, kv, event, wal_size_mb
from shield.common.models import Alert


# --- định dạng ---------------------------------------------------------------


def test_kv_quotes_only_when_needed_and_keeps_order():
    assert kv(rule="LOCAL_SSH_BRUTEFORCE", risk=65, ok=True) == "rule=LOCAL_SSH_BRUTEFORCE risk=65 ok=True"
    assert kv(title="SSH bị dò", n=3) == 'title="SSH bị dò" n=3'
    assert kv(a=None, b=1) == "b=1", "giá trị None bị bỏ, không in 'None'"
    assert kv(took=2.50) == "took=2.5" and kv(took=3.0) == "took=3"
    assert kv(q='say "hi"') == 'q="say \\"hi\\""'
    assert event("heartbeat", up=5) == "heartbeat up=5" and event("x") == "x"


def test_rate_limiter_counts_what_it_suppressed():
    clock = [0.0]
    limiter = RateLimiter(interval_s=10, clock=lambda: clock[0])
    assert limiter.allow("k") == (True, 0)
    assert limiter.allow("k") == (False, 0) and limiter.allow("k") == (False, 0)
    clock[0] = 11
    assert limiter.allow("k") == (True, 2)
    assert limiter.allow("other") == (True, 0)


# --- theo dõi khoá -------------------------------------------------------------


def test_tracked_lock_reports_owner_duration_and_label():
    lock = TrackedRLock(slow_hold_s=10)
    assert not lock.snapshot().held
    started, release = threading.Event(), threading.Event()

    def holder():
        with lock:
            lock.label("DELETE FROM graph_entities WHERE ...")
            started.set()
            release.wait(5)

    thread = threading.Thread(target=holder, name="maintenance-thread")
    thread.start()
    started.wait(5)
    time.sleep(0.05)
    snap = lock.snapshot()
    assert snap.held and snap.thread == "maintenance-thread"
    assert snap.label.startswith("DELETE FROM graph_entities") and snap.held_for_s >= 0.04
    release.set()
    thread.join(5)
    assert not lock.snapshot().held
    stats = lock.drain_stats()
    assert stats["max_hold_s"] >= 0.04 and lock.drain_stats()["max_hold_s"] == 0.0


def test_tracked_lock_is_reentrant_and_counts_one_hold():
    lock = TrackedRLock(slow_hold_s=10)
    with lock:
        with lock:
            assert lock.snapshot().held
    assert not lock.snapshot().held


def test_a_long_lock_hold_is_logged_with_what_it_was_doing(tmp_path, caplog, monkeypatch):
    from shield.agent import store as store_module

    monkeypatch.setattr(store_module, "_SLOW_LOG", RateLimiter(interval_s=0))
    store = Store(tmp_path / "s.db")
    store.conn._lock.slow_hold_s = 0.05
    with caplog.at_level(logging.WARNING, logger="shield.store"):
        with store.conn:
            store.conn.execute("SELECT 1")
            time.sleep(0.12)
    assert "lock_held_long" in caplog.text and "doing=" in caplog.text
    assert "SELECT 1" in caplog.text


def test_a_slow_statement_is_logged_with_its_sql(tmp_path, caplog, monkeypatch):
    from shield.agent import store as store_module

    monkeypatch.setattr(store_module, "SLOW_SQL_S", 0.0)
    monkeypatch.setattr(store_module, "_SLOW_LOG", RateLimiter(interval_s=0))
    store = Store(tmp_path / "s.db")
    with caplog.at_level(logging.WARNING, logger="shield.store"):
        store.conn.execute("SELECT count(*) FROM events")
    assert "slow_sql" in caplog.text and "SELECT count(*) FROM events" in caplog.text


# --- watchdog ---------------------------------------------------------------------


def test_a_slow_watchdog_ping_names_the_lock_holder(tmp_path, caplog):
    store = Store(tmp_path / "s.db")
    started, release = threading.Event(), threading.Event()

    def holder():
        with store.conn._lock:
            store.conn._lock.label("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts LIMIT ?)")
            started.set()
            release.wait(5)

    thread = threading.Thread(target=holder, name="to_thread-maintenance")
    thread.start()
    started.wait(5)

    async def scenario():
        asyncio.get_running_loop().call_later(0.4, release.set)
        return await agent.check_store_alive(store, slow_after_s=0.1)

    with caplog.at_level(logging.WARNING, logger="shield.agent"):
        assert asyncio.run(scenario()) is True
    thread.join(5)
    assert "watchdog_ping_slow" in caplog.text
    assert "holder_thread=to_thread-maintenance" in caplog.text
    assert "holder_doing=" in caplog.text and "DELETE FROM events" in caplog.text
    assert "watchdog_ping_recovered" in caplog.text


def test_a_fast_watchdog_ping_is_silent(tmp_path, caplog):
    store = Store(tmp_path / "s.db")
    with caplog.at_level(logging.WARNING, logger="shield.agent"):
        assert asyncio.run(agent.check_store_alive(store)) is True
    assert "watchdog_ping" not in caplog.text


# --- các dòng vận hành -------------------------------------------------------------


def test_the_alert_line_carries_rule_scores_and_subject(tmp_path, caplog):
    class Ipc:
        async def broadcast(self, *a):
            pass

    async def scenario():
        store = Store(tmp_path / "s.db")
        bus = Bus()
        task = asyncio.create_task(agent.run_alert_consumer(bus, store, Ipc()))
        await asyncio.sleep(0)
        await bus.publish(Alert(time.time(), "LOCAL_SSH_BRUTEFORCE", "warning", "SSH bị dò", "d",
                                "203.0.113.7", evidence={"src_ip": "203.0.113.7", "fail_count": 25}))
        for _ in range(300):
            await asyncio.sleep(0.01)
            if store.recent_alerts():
                break
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    with caplog.at_level(logging.INFO, logger="shield.agent"):
        asyncio.run(scenario())
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("alert "))
    for field in ("id=", "rule=LOCAL_SSH_BRUTEFORCE", "severity=warning", "risk=", "confidence=",
                  "subject=203.0.113.7", "action="):
        assert field in line, (field, line)


def test_the_maintenance_line_reports_steps_sizes_and_next_run(tmp_path, caplog, monkeypatch):
    monkeypatch.setattr(agent, "MAINTENANCE_INTERVAL_S", 0.01)
    monkeypatch.setattr(agent, "MAINTENANCE_BUSY_INTERVAL_S", 0.01)

    async def scenario():
        store = Store(tmp_path / "s.db")
        task = asyncio.create_task(agent.maintenance_loop(store, Bus()))
        for _ in range(300):
            await asyncio.sleep(0.02)
            if any("maintenance_pass" in r.getMessage() for r in caplog.records):
                break
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    with caplog.at_level(logging.INFO, logger="shield.agent"):
        asyncio.run(scenario())
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("maintenance_pass"))
    for field in ("n=1", "took_s=", "result=", "db_used_mb=", "db_cap_mb=", "over_cap=", "wal_mb=",
                  "steps=retention_and_size_cap:", "next_in_s="):
        assert field in line, (field, line)


def test_the_heartbeat_reports_health(tmp_path, caplog):
    async def scenario():
        store = Store(tmp_path / "s.db")
        task = asyncio.create_task(agent.heartbeat_loop(store, Bus(), Bus(), interval_s=0.05))
        for _ in range(100):
            await asyncio.sleep(0.03)
            if any(r.getMessage().startswith("heartbeat") for r in caplog.records):
                break
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    with caplog.at_level(logging.INFO, logger="shield.agent"):
        asyncio.run(scenario())
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("heartbeat"))
    for field in ("uptime_s=", "events_per_s=", "queue_events=", "dropped_events=", "rss_mb=",
                  "db_used_mb=", "wal_mb=", "lock_max_wait_s=", "lock_max_hold_s=", "lock_slow_holds="):
        assert field in line, (field, line)


def test_the_startup_banner_says_what_is_running(tmp_path, caplog):
    import argparse

    store = Store(tmp_path / "s.db")
    args = argparse.Namespace(discover=True, mitm=True, portscan=False, dns=False, journal=True,
                              endpoint=True, fim_path=["/etc/hosts"])
    with caplog.at_level(logging.INFO, logger="shield.agent"):
        agent.log_startup_banner(store, args)
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("agent_starting"))
    for field in ("version=", "python=", "pid=", "db=", "db_used_mb=", "wal_mb=", "schema=",
                  "capabilities=", "collectors=discover,mitm,journal,endpoint", "fim_paths=1"):
        assert field in line, (field, line)


def test_the_desktop_notification_warning_is_throttled(caplog, monkeypatch):
    from shield.agent import notifier
    from shield.common.diaglog import RateLimiter as Limiter

    monkeypatch.setattr(notifier, "_NOTIFY_LOG", Limiter(interval_s=600))
    monkeypatch.setattr(notifier.os, "geteuid", lambda: 0)

    async def relay(payload):
        return 0

    notifier.set_desktop_relay(relay)
    alert = Alert(1.0, "R", "critical", "t", "d", "s")
    try:
        with caplog.at_level(logging.WARNING, logger="shield.notifier"):
            for _ in range(20):
                asyncio.run(notifier.notify_desktop(alert))
    finally:
        notifier.set_desktop_relay(None)
    lines = [r for r in caplog.records if "desktop_notification_not_delivered" in r.getMessage()]
    assert len(lines) == 1, "20 thông báo hụt phải ra MỘT dòng"


def test_the_log_format_has_millisecond_time_and_padded_level():
    from shield.common.diaglog import LOG_FORMAT

    record = logging.LogRecord("shield.agent", logging.INFO, "f", 1, "heartbeat x=1", None, None)
    text = logging.Formatter(LOG_FORMAT, "%Y-%m-%d %H:%M:%S").format(record)
    assert text.endswith("INFO    shield.agent: heartbeat x=1")
    assert wal_size_mb("/nonexistent/db") == 0.0
