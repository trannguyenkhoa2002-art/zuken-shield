import asyncio
import time

from shield.agent.bus import Bus
from shield.agent.store import Store
from shield.benchmark import run_benchmark
from shield.common.models import Alert, Event


def test_bus_is_bounded_and_reports_backpressure():
    async def scenario():
        bus = Bus(max_queue_size=1)
        queue = bus.subscribe()
        await bus.publish("first")
        pending = asyncio.create_task(bus.publish("second"))
        await asyncio.sleep(0)
        assert not pending.done()
        assert bus.stats()["backpressure_count"] == 1
        assert await queue.get() == "first"
        await pending
        assert await queue.get() == "second"
    asyncio.run(scenario())


def test_store_maintenance_prunes_operational_data_not_forensics(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    old = time.time() - 400 * 86400
    store.insert_event(Event(old, "test", "old", {}))
    store.insert_alert(Alert(old, "OLD", "info", "old", "old", "subject"), dedupe_window_s=0)
    store.add_forensic_record("must-remain", {"id": 1})
    result = store.maintain(event_days=30, alert_days=365)
    assert result["events_deleted"] == 1
    assert result["alerts_deleted"] == 1
    assert store.verify_forensic_ledger()[0]
    count = store.conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()[0]
    assert count == 1
    store.close()


def test_benchmark_returns_machine_readable_thresholds():
    result = run_benchmark(iterations=1)
    assert result["iterations"] == 1
    assert result["mean_ms"] >= 0
    assert "max_rss_kib" in result
    assert result["thresholds"]["mean_ms"] == 1000
