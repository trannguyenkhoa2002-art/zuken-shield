"""Nâng cấp không chép database hai lần — nhưng chỉ khi chứng minh được là cùng trạng thái.

Máy thật 29/09/2026: preinst chép 2,9 GB lúc 18:22:04, agent chép lại đúng
trạng thái đó 36 giây sau, trước migration v10 -> v11.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import time

from shield.agent.store import SCHEMA_VERSION, Store


def _old_database(tmp_path):
    path = tmp_path / "shield.db"
    store = Store(path)
    store.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION - 1}")
    store.conn.commit()
    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    store.close()
    past = time.time() - 600
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / f"shield.db{suffix}"
        if p.exists():
            os.utime(p, (past, past))
    return path


def _pre_upgrade(tmp_path, path, *, age_s=60.0, version=None):
    backups = tmp_path / "backups"
    backups.mkdir(exist_ok=True)
    target = backups / f"shield-pre-upgrade-{int(time.time())}.db"
    shutil.copy2(path, target)
    if version is not None:
        conn = sqlite3.connect(target)
        conn.execute(f"PRAGMA user_version={version}")
        conn.commit()
        conn.close()
    stamp = time.time() - age_s
    os.utime(target, (stamp, stamp))
    return backups


def _pre_migration(backups):
    return sorted(p.name for p in backups.glob("shield-pre-migration-*.db"))


def test_a_fresh_identical_pre_upgrade_copy_is_reused(tmp_path):
    path = _old_database(tmp_path)
    backups = _pre_upgrade(tmp_path, path)
    Store(path, allow_migration=True)
    assert _pre_migration(backups) == [], "đã có bản sao cùng trạng thái, không chép lần hai"


def test_a_stale_pre_upgrade_copy_is_not_trusted(tmp_path):
    path = _old_database(tmp_path)
    backups = _pre_upgrade(tmp_path, path, age_s=3 * 3600)
    Store(path, allow_migration=True)
    assert len(_pre_migration(backups)) == 1


def test_a_database_changed_after_the_copy_gets_its_own_backup(tmp_path):
    path = _old_database(tmp_path)
    backups = _pre_upgrade(tmp_path, path)
    os.utime(path, None)                       # database sửa SAU lúc chép
    Store(path, allow_migration=True)
    assert len(_pre_migration(backups)) == 1


def test_a_copy_of_another_schema_version_is_not_reused(tmp_path):
    path = _old_database(tmp_path)
    backups = _pre_upgrade(tmp_path, path, version=SCHEMA_VERSION - 3)
    Store(path, allow_migration=True)
    assert len(_pre_migration(backups)) == 1


def test_a_non_empty_wal_written_after_the_copy_blocks_reuse(tmp_path):
    path = _old_database(tmp_path)
    backups = _pre_upgrade(tmp_path, path)
    wal = tmp_path / "shield.db-wal"
    wal.write_bytes(b"x" * 64)                 # có khung ghi SAU lúc chép
    try:
        Store(path, allow_migration=True)
    except sqlite3.DatabaseError:
        pass                                   # WAL giả hỏng không quan trọng: điều cần kiểm là quyết định sao lưu
    assert len(_pre_migration(backups)) == 1
