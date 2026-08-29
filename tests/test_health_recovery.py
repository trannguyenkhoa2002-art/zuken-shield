import asyncio
import os
import sqlite3
from pathlib import Path
import time

import pytest

from shield.agent.bus import Bus
from shield.agent.store import DatabaseIntegrityError, SCHEMA_VERSION, Store
from shield.common.models import Alert
from shield.security.health import CollectorSupervisor, prune_managed_files


def test_corrupt_database_is_preserved_and_refused(tmp_path):
    path = tmp_path / "shield.db"
    original = b"not-a-sqlite-database"
    path.write_bytes(original)
    with pytest.raises(DatabaseIntegrityError):
        Store(path)
    assert path.read_bytes() == original


def test_schema_migration_creates_pre_migration_backup(tmp_path):
    path = tmp_path / "shield.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE legacy(value TEXT)")
    conn.execute("INSERT INTO legacy VALUES('preserve-me')")
    conn.execute("PRAGMA user_version=1")
    conn.commit()
    conn.close()

    # Đây là test CỦA migration, nên phải xin quyền tường minh — từ 2.0 mặc
    # định là không migrate (giao diện đã sập vì mặc định cũ cho phép).
    store = Store(path, allow_migration=True)
    assert store.database_stats()["schema_version"] == SCHEMA_VERSION
    backups = list((tmp_path / "backups").glob("shield-pre-migration-v1-*.db"))
    assert len(backups) == 1
    backup = sqlite3.connect(backups[0])
    assert backup.execute("SELECT value FROM legacy").fetchone()[0] == "preserve-me"
    backup.close()
    store.close()


def test_alert_dedup_keeps_first_last_count_and_distinct_sources(tmp_path):
    store = Store(tmp_path / "shield.db")
    first = Alert(time.time(), "RULE", "warning", "title", "detail", "host",
                  evidence={"collector": "dns"})
    second = Alert(first.ts + 1, "RULE", "critical", "title", "detail", "host",
                   evidence={"collector": "journal"}, risk_score=90, evidence_strength=0.9)
    store.insert_alert(first)
    store.insert_alert(second)
    row = store.recent_alerts(1)[0]
    assert row["count"] == 2
    assert row["first_seen"] == first.ts
    assert row["last_seen"] == second.ts
    assert row["source_count"] == 2
    assert row["risk_score"] == 90
    store.close()


def test_pcap_pruning_is_bounded_and_does_not_follow_symlinks(tmp_path):
    root = tmp_path / "pcaps"
    root.mkdir()
    old = root / "old.pcap"
    old.write_bytes(b"x" * 20)
    os.utime(old, (1, 1))
    keep = root / "note.txt"
    keep.write_text("keep")
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"outside")
    (root / "link.pcap").symlink_to(outside)

    result = prune_managed_files(root, retention_days=1, maximum_bytes=1024)
    assert result["deleted"] == 1
    assert not old.exists()
    assert keep.exists()
    assert outside.read_bytes() == b"outside"


def test_collector_supervisor_stops_restart_loop_and_alerts(tmp_path):
    async def scenario():
        store = Store(tmp_path / "shield.db")
        alerts = Bus(max_queue_size=10)
        queue = alerts.subscribe()
        attempts = 0

        async def broken():
            nonlocal attempts
            attempts += 1
            raise RuntimeError("boom")

        supervisor = CollectorSupervisor(
            store, alerts, max_crashes=2, crash_window_s=60,
            heartbeat_s=1, restart_backoff_s=0,
        )
        await supervisor.run("broken", "test", broken)
        health = {item["component"]: item for item in store.collector_health()}
        assert attempts == 2
        assert health["broken"]["state"] == "failed"
        assert health["broken"]["restart_count"] == 2
        alert = await queue.get()
        assert alert.rule_id == "SHIELD_COLLECTOR_FAILED"
        store.close()

    asyncio.run(scenario())


def test_drop_oldest_bus_bounds_event_storm():
    async def scenario():
        bus = Bus(max_queue_size=2, overflow_policy="drop_oldest")
        queue = bus.subscribe()
        await bus.publish("one")
        await bus.publish("two")
        await bus.publish("three")
        assert [await queue.get(), await queue.get()] == ["two", "three"]
        assert bus.stats()["dropped"] == 1

    asyncio.run(scenario())


def test_agent_mode_rebuilds_a_corrupt_database_instead_of_crash_looping(tmp_path):
    """Mục B3. Trước đây agent ném DatabaseIntegrityError lúc khởi động, systemd
    restart, rồi hỏng lại — máy mất giám sát hoàn toàn cho tới khi có người sửa
    tay. Bây giờ agent phải tự đứng dậy."""
    path = tmp_path / "shield.db"
    path.write_bytes(b"not-a-sqlite-database")

    store = Store(path, recover_corrupt=True)
    try:
        assert store.recovery is not None
        assert store.check_integrity()[0] is True
        # DB hỏng được GIỮ LẠI làm bằng chứng, không bị xoá.
        quarantined = Path(store.recovery["quarantined_path"])
        assert quarantined.exists()
        assert quarantined.read_bytes() == b"not-a-sqlite-database"
        # Và việc phục hồi phải nhìn thấy được, không im lặng.
        assert store.get_baseline("recovered_from_corruption_ts")
    finally:
        store.close()


def test_recovery_rescues_the_rows_that_are_still_readable(tmp_path):
    """Hỏng một phần thì không được vứt cả file — phần đọc được phải cứu."""
    path = tmp_path / "shield.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE keepme(value TEXT)")
    conn.executemany("INSERT INTO keepme VALUES(?)", [(f"row-{i}",) for i in range(50)])
    conn.commit()
    conn.close()
    # Phá header để SQLite coi là hỏng, phần đuôi file vẫn còn nguyên.
    blob = bytearray(path.read_bytes())
    blob[24:40] = b"\xff" * 16
    path.write_bytes(bytes(blob))

    store = Store(path, recover_corrupt=True)
    try:
        assert store.recovery is not None
        # ">= 0" là điều kiện luôn đúng — chính nó đã che lỗi phục hồi trả về
        # DB rỗng. Phải đòi dữ liệu thật sự còn đó.
        assert store.recovery["rows_recovered"] >= 50
        rows = store.conn.execute("SELECT count(*) FROM keepme").fetchone()[0]
        assert rows == 50
        assert store.check_integrity()[0] is True
    finally:
        store.close()


def test_default_store_still_refuses_to_touch_a_corrupt_database(tmp_path):
    """UI, CLI và script điều tra dùng mặc định — chúng không được phép tự ý
    dời database của người dùng đi chỗ khác."""
    path = tmp_path / "shield.db"
    path.write_bytes(b"not-a-sqlite-database")
    with pytest.raises(DatabaseIntegrityError):
        Store(path)
    assert path.exists()
    assert not list(tmp_path.glob("*.corrupt.*"))


def _corrupt_region(path, seed=11, patches=60, start=0.5, stop=1.0):
    """Phá một vùng của file. `start`/`stop` là tỉ lệ vị trí trong file.

    Vùng cuối = chỉ chạm trang dữ liệu (hỏng đĩa thường gặp, cứu được phần lớn).
    Vùng đầu = chạm cả trang schema (SQLite không đọc nổi sqlite_master, đường
    SQL hết cách — lúc đó phải quay về bản sao lưu).
    """
    import random

    with open(path, "r+b") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        low, high = int(size * start), max(int(size * stop) - 256, int(size * start) + 1)
        random.seed(seed)
        for _ in range(patches):
            handle.seek(random.randrange(low, high))
            handle.write(bytes(random.randrange(256) for _ in range(256)))


def test_recovery_actually_keeps_rows(tmp_path):
    """Phục hồi phải CỨU ĐƯỢC dữ liệu, không chỉ chạy xong mà không lỗi.

    Bản trước dùng iterdump() và trả về DB rỗng trong khi vẫn báo "recovered
    N" — con số đếm câu lệnh đã chạy, còn lỗi từ generator nhảy qua commit()
    nên tất cả bị rollback. Hỏng kiểu này im lặng tuyệt đối: agent chạy tiếp,
    log nói phục hồi thành công, và toàn bộ bằng chứng đã biến mất.
    """
    import sqlite3

    from shield.agent.store import Store
    from shield.common.models import Event

    path = tmp_path / "shield.db"
    store = Store(path)
    for i in range(5000):
        store.insert_event(Event(1000.0 + i, "journal", "test", {"i": i}))
    store.close()
    del store

    before = sqlite3.connect(path).execute("SELECT count(*) FROM events").fetchone()[0]
    assert before == 5000
    # Ít mảng hỏng, nằm ở đuôi file: mô phỏng hỏng đĩa khu trú, phần lớn
    # trang dữ liệu còn nguyên.
    _corrupt_region(path, patches=6, start=0.75, stop=1.0)

    recovered = Store(path, recover_corrupt=True)
    assert recovered.recovery, "không nhận ra database hỏng"
    after = sqlite3.connect(path).execute("SELECT count(*) FROM events").fetchone()[0]
    # Không đòi 100% — trang hỏng thì mất thật. Đòi phần lớn phải còn.
    assert after >= before * 0.5, f"chỉ cứu được {after}/{before} dòng"
    assert recovered.recovery["rows_recovered"] >= after
    # Bản hỏng là bằng chứng, không được xoá.
    assert list(tmp_path.glob("shield.db.corrupt.*"))


def test_a_backup_is_used_when_nothing_can_be_salvaged(tmp_path):
    """Hỏng trúng trang schema thì đường SQL bó tay — phải quay về bản sao lưu.

    Mất trắng lịch sử trong khi một bản sao lưu lành lặn nằm ngay thư mục bên
    cạnh là kiểu hỏng không có lý do gì để tồn tại.
    """
    import sqlite3

    from shield.agent.store import Store
    from shield.common.models import Event

    path = tmp_path / "shield.db"
    store = Store(path)
    for i in range(500):
        store.insert_event(Event(1000.0 + i, "journal", "test", {"i": i}))
    store.backup_database(tmp_path / "backups" / "daily.db")
    del store

    # Phá cả vùng đầu file, nơi đặt trang schema.
    _corrupt_region(path, seed=3, patches=200, start=0.0, stop=1.0)

    recovered = Store(path, recover_corrupt=True)
    assert recovered.recovery["restored_from_backup"], "không dùng tới bản sao lưu"
    after = sqlite3.connect(path).execute("SELECT count(*) FROM events").fetchone()[0]
    assert after == 500


def test_a_corrupt_backup_is_never_restored(tmp_path):
    """Bản sao lưu chép từ DB đã hỏng chỉ đổi kiểu hỏng, không sửa được gì."""
    from shield.agent.store import Store
    from shield.common.models import Event

    path = tmp_path / "shield.db"
    store = Store(path)
    for i in range(500):
        store.insert_event(Event(1000.0 + i, "journal", "test", {"i": i}))
    store.backup_database(tmp_path / "backups" / "daily.db")
    del store
    _corrupt_region(tmp_path / "backups" / "daily.db", seed=5, patches=200, start=0.0, stop=1.0)
    _corrupt_region(path, seed=3, patches=200, start=0.0, stop=1.0)

    recovered = Store(path, recover_corrupt=True)
    assert recovered.recovery["restored_from_backup"] is None


def test_the_database_size_cap_is_actually_enforced(tmp_path):
    """`database_max_bytes` phải CẮT dữ liệu, không chỉ tô màu cảnh báo.

    Trước đây tham số này chỉ dùng để hiện "degraded" trong tab Sức khoẻ trong
    khi database cứ lớn mãi. Một con số trông như giới hạn nhưng không giới hạn
    gì thì tệ hơn là không có, vì người đọc tin rằng đã có ai đó lo phần này.
    """
    from shield.agent.store import Store
    from shield.common.models import Event

    store = Store(tmp_path / "big.db")
    for i in range(20000):
        store.insert_event(Event(1_700_000_000.0 + i, "kernel", "exec", {"payload": "x" * 200}))
    store.conn.commit()
    size_before = store.database_bytes()
    assert size_before > 400_000, size_before

    result = store.maintain(event_days=3650, alert_days=3650, snapshot_days=3650,
                            database_max_bytes=size_before // 2)
    assert result["events_trimmed_for_size"] > 0, "trần dung lượng không cắt gì cả"
    assert store.database_bytes() < size_before
    # Phải xoá từ CŨ NHẤT: event mới là thứ đang điều tra.
    oldest = store.conn.execute("SELECT min(ts) FROM events").fetchone()[0]
    assert oldest is None or oldest > 1_700_000_000.0
    store.close()


def test_no_cap_means_no_trimming(tmp_path):
    from shield.agent.store import Store
    from shield.common.models import Event

    store = Store(tmp_path / "small.db")
    for i in range(100):
        store.insert_event(Event(1_700_000_000.0 + i, "kernel", "exec", {}))
    result = store.maintain(event_days=3650, alert_days=3650, snapshot_days=3650)
    assert result["events_trimmed_for_size"] == 0
    assert store.conn.execute("SELECT count(*) FROM events").fetchone()[0] == 100
    store.close()


def test_a_database_with_undecodable_bytes_is_still_recoverable(tmp_path):
    """Byte rác trong vùng text KHÔNG được làm sập cả đường phục hồi.

    sqlite3 giải mã text bằng UTF-8 nghiêm ngặt và ném `UnicodeDecodeError` —
    một lỗi KHÔNG phải `DatabaseError`, nên nó thoát khỏi mọi `except` trên
    đường phục hồi và giết agent ngay ở bước kiểm tra. Nghĩa là: database hỏng
    đúng kiểu hay gặp nhất là database duy nhất không cứu được.
    """
    from shield.agent.store import Store

    path = tmp_path / "shield.db"
    store = Store(path, allow_migration=True)
    store.conn.execute("INSERT INTO baseline(key,value,set_ts) VALUES('k','v',1)")
    store.conn.commit()
    store.close()

    raw = bytearray(path.read_bytes())
    # Rải byte không hợp lệ UTF-8 vào vùng dữ liệu, giữ nguyên header.
    for offset in range(4096, min(len(raw), 20000), 97):
        raw[offset] = 0xA4
    path.write_bytes(bytes(raw))

    recovered = Store(path, recover_corrupt=True, allow_migration=True)
    try:
        assert recovered.recovery is not None
        # Điều quan trọng không phải cứu được bao nhiêu, mà là KHÔNG NÉM ra
        # ngoài và database mới dùng được.
        assert recovered.conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        recovered.close()


def test_the_integrity_check_never_raises_on_a_broken_database(tmp_path):
    """Cơ chế phát hiện hỏng hóc không được tự sập vì đúng thứ nó phát hiện."""
    import sqlite3

    from shield.agent.store import Store

    path = tmp_path / "probe.db"
    Store(path, allow_migration=True).close()
    raw = bytearray(path.read_bytes())
    for offset in range(4096, min(len(raw), 20000), 53):
        raw[offset] = 0xA4
    path.write_bytes(bytes(raw))

    conn = sqlite3.connect(path)
    store = Store.__new__(Store)
    from shield.agent.store import _ThreadSafeConnection

    store.conn = _ThreadSafeConnection(conn)
    ok, message = store.check_integrity(quick=True)
    assert ok is False
    assert message
    conn.close()
