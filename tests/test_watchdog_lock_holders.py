"""Không việc bảo trì dài nào được giữ cái khoá mà ping watchdog cần.

Sự cố có thật, sau bản sửa ping-sớm của Beta 1.0: journal ghi 41 lần watchdog
timeout từ 29/08 tới 27/09/2026, và ngày 27/09 agent nằm ở `failed` sau năm
lần SIGABRT liên tiếp. Dấu vết trên đĩa: một file `backups/shield-*.db.tmp`
dở dang đúng giờ bị giết — backup hằng ngày 2,5 GB chạy qua `self.conn`, tức
giữ khoá `_ThreadSafeConnection` suốt lượt chép, trong khi `watchdog_loop`
chứng minh store còn sống bằng `get_baseline` trên chính khoá đó. Khởi động
lại thì backup vẫn tới hạn, nên chết lặp lại cho tới khi systemd bỏ cuộc.

Các lần boot nguội khác chết TRƯỚC dòng log khởi động đầu tiên: khởi động dài
hơn 90 giây, mà `Type=simple` đếm watchdog từ lúc tiến trình bắt đầu.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

from shield.agent.store import Store
from shield.common.models import Event

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "shield" / "agent" / "__main__.py"
UNIT = ROOT / "systemd" / "shield-agent.service"


def _store_with_data(tmp_path, count=2000):
    store = Store(tmp_path / "s.db")
    for index in range(count):
        store.insert_event(Event(time.time(), "test", "process_exec", {"i": index, "pad": "x" * 200}))
    store.conn.commit()
    return store


def _holds_shared_lock_during(store, operation) -> bool:
    """Chạy `operation` trong khi một luồng khác đang giữ khoá chung.

    Nếu `operation` cần khoá chung thì nó phải chờ; ta thả khoá sau 1 giây và
    đo. Không cần khoá thì nó xong ngay trong lúc khoá còn bị giữ.
    """
    held = threading.Event()
    release = threading.Event()

    def holder():
        with store.conn._lock:
            held.set()
            release.wait(5)

    thread = threading.Thread(target=holder)
    thread.start()
    held.wait(5)
    finished = threading.Event()

    def run():
        operation()
        finished.set()

    worker = threading.Thread(target=run)
    worker.start()
    completed_while_locked = finished.wait(1.0)
    release.set()
    worker.join(10)
    thread.join(5)
    return not completed_while_locked


def test_the_daily_backup_does_not_take_the_shared_lock(tmp_path):
    store = _store_with_data(tmp_path)
    target = tmp_path / "backups" / "shield-1.db"
    assert not _holds_shared_lock_during(store, lambda: store.backup_database(target)), (
        "backup chép cả database trong lúc giữ khoá mà watchdog cần")
    assert target.exists()
    copy = Store(target)
    assert copy.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2000


def test_the_backup_is_a_consistent_copy_while_the_agent_keeps_writing(tmp_path):
    store = _store_with_data(tmp_path)
    target = tmp_path / "backups" / "shield-2.db"
    store.backup_database(target)
    store.insert_event(Event(time.time(), "test", "process_exec", {"after": True}))
    store.conn.commit()
    copy = Store(target)
    assert copy.check_integrity() == (True, "ok")
    assert copy.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2000


def test_the_maintenance_integrity_check_does_not_take_the_shared_lock(tmp_path):
    store = _store_with_data(tmp_path)
    result = {}

    def check():
        result["value"] = store.check_integrity(separate_connection=True)

    assert not _holds_shared_lock_during(store, check)
    assert result["value"] == (True, "ok")


def test_the_maintenance_loop_uses_the_separate_connection_and_a_daily_cadence():
    source = AGENT.read_text(encoding="utf-8")
    start = source.index("async def maintenance_loop(")
    body = source[start:source.index("\ndef ", start)]
    assert "separate_connection=True" in body
    assert "database_last_integrity_check" in body
    assert "INTEGRITY_CHECK_INTERVAL_S" in body
    assert re.search(r"^INTEGRITY_CHECK_INTERVAL_S = 86400$", source, re.MULTILINE)


# --- Type=notify ---------------------------------------------------------


def test_the_agent_unit_starts_the_watchdog_only_after_ready():
    unit = UNIT.read_text(encoding="utf-8")
    assert re.search(r"^Type=notify$", unit, re.MULTILINE)
    assert re.search(r"^NotifyAccess=main$", unit, re.MULTILINE)
    start = int(re.search(r"^TimeoutStartSec=(\d+)$", unit, re.MULTILINE).group(1))
    assert start >= 180, "khởi động nguội đã vượt 90 giây trên máy thật"
    # Không nới phát hiện treo.
    assert re.search(r"^WatchdogSec=90$", unit, re.MULTILINE)


def test_ready_is_sent_only_after_the_store_answers():
    source = AGENT.read_text(encoding="utf-8")
    start = source.index("async def watchdog_loop(")
    body = source[start:source.index("\nasync def ", start + 1)]
    first_alive = body.index("if await alive():")
    first_ready = body.index('notify("READY=1")')
    assert first_alive < first_ready


# --- sao lưu có giới hạn --------------------------------------------------


def _touch(path: Path, size: int = 10) -> None:
    path.write_bytes(b"x" * size)


def test_backups_are_pruned_per_family_and_stale_temporaries_removed(tmp_path):
    store = Store(tmp_path / "shield.db")
    backups = tmp_path / "backups"
    backups.mkdir()
    for ts in (100, 200, 300, 400, 500):
        _touch(backups / f"shield-{ts}.db")
        _touch(backups / f"shield-pre-upgrade-{ts}.db")
    _touch(backups / "shield-600.db.tmp")
    _touch(backups / "shield-600.db.tmp-journal")
    keep_out = [
        backups / "shield-pre-migration-v9-100.db",
        backups / "operator-copy.db",
    ]
    for path in keep_out:
        _touch(path)

    result = store.prune_backups(keep=3)

    names = sorted(p.name for p in backups.iterdir())
    assert [n for n in names if re.fullmatch(r"shield-\d+\.db", n)] == [
        "shield-300.db", "shield-400.db", "shield-500.db"]
    assert [n for n in names if n.startswith("shield-pre-upgrade-")] == [
        "shield-pre-upgrade-300.db", "shield-pre-upgrade-400.db", "shield-pre-upgrade-500.db"]
    assert not any(n.endswith((".tmp", ".tmp-journal")) for n in names)
    for path in keep_out:
        assert path.exists(), f"{path.name} không thuộc sao lưu tự động, không được xoá"
    assert result["deleted"] == 4
    assert result["temporary_deleted"] == 2


def test_backup_pruning_never_follows_symlinks(tmp_path):
    store = Store(tmp_path / "shield.db")
    backups = tmp_path / "backups"
    backups.mkdir()
    outside = tmp_path / "outside.db"
    _touch(outside)
    for ts in (1, 2, 3, 4):
        _touch(backups / f"shield-{ts}.db")
    os.symlink(outside, backups / "shield-0.db")
    store.prune_backups(keep=1)
    assert outside.exists()


# --- size cap giữ bằng chứng gốc -----------------------------------------


def test_the_size_cap_prunes_orphaned_graph_before_deleting_real_events(tmp_path):
    from tests.test_maintenance_bounds import _edges

    store = Store(tmp_path / "s.db")
    _edges(store, 500)  # 500 cạnh mồ côi
    live = [Event(time.time(), "test", "process_exec", {"i": i}) for i in range(300)]
    for event in live:
        store.insert_event(event)
    store.conn.commit()

    removed = store._enforce_size_cap(1)  # trần nhỏ tới mức luôn ở trên

    assert removed == 0, "còn cạnh mồ côi mà đã xoá event thật"
    assert store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 300
    assert store.conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0] == 0


def test_the_size_cap_still_trims_events_once_the_graph_is_clean(tmp_path):
    store = Store(tmp_path / "s.db")
    for index in range(300):
        store.insert_event(Event(time.time(), "test", "process_exec", {"i": index}))
    store.conn.commit()
    assert store._enforce_size_cap(1, batch=100) == 100


def test_backups_are_pruned_after_the_new_copy_exists():
    """Dọn trước khi chép để lại keep+1 bản (thấy trên máy thật) và có thể xoá
    một bản tốt trước khi bản mới chép xong."""
    source = AGENT.read_text(encoding="utf-8")
    start = source.index("async def maintenance_loop(")
    body = source[start:source.index("\ndef ", start)]
    assert body.index("store.backup_database") < body.index("store.prune_backups")
