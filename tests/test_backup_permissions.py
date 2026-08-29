"""Sao lưu trước khi đổi schema — và cái bẫy quyền đã chặn nó trên máy thật.

Mô hình quyền cố ý của Shield:

    /var/lib/shield            drwxrwx---  root:shield
    /var/lib/shield/shield.db  -rw-rw----  root:shield

Nhóm `shield` ghi được database. Nhưng `backups/` do một lượt chạy root tạo ra
với umask mặc định lại thành `drwx------ root:root`, và không có chỗ nào sửa
lại. Thành viên nhóm vì thế ghi được database mà KHÔNG ghi được bản sao lưu của
nó, nên mọi lượt nâng cấp schema chết ở đúng dòng này:

    sqlite3.OperationalError: unable to open database file

Một thông báo không nói gì về quyền, nên người đọc đi tìm database hỏng.
"""

from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from shield.agent.store import SCHEMA_VERSION, Store, default_db_path


def _make_v9(path):
    store = Store(path, allow_migration=True)
    store.conn.execute("DROP INDEX IF EXISTS idx_incident_alerts_alert")
    store.conn.execute("DROP TABLE incident_correlation_reasons")
    store.conn.execute("DROP TABLE incident_refs")
    store.conn.execute("ALTER TABLE incident_alerts DROP COLUMN alert_id")
    store.conn.execute("PRAGMA user_version=9")
    store.conn.execute(
        "INSERT INTO events(ts,source,kind,data,event_id) VALUES(1.0,'t','k','{}','ev-1')")
    store.conn.commit()
    store.close()


# --- 1. thư mục sao lưu chưa tồn tại ---


def test_migration_creates_the_backup_when_the_directory_is_missing(tmp_path):
    path = tmp_path / "shield.db"
    _make_v9(path)
    assert not (tmp_path / "backups").exists()

    store = Store(path, allow_migration=True)
    assert store.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION

    backups = sorted((tmp_path / "backups").glob("shield-pre-migration-v9-*.db"))
    assert len(backups) == 1


# --- 2. không ghi được -> fail closed, thông báo nói ra chuyện gì ---


@pytest.fixture
def unowned_backups(tmp_path, monkeypatch):
    """Thư mục sao lưu mà tiến trình KHÔNG sở hữu.

    Đúng tình huống thật: `backups/` là `root:root` còn agent chạy dưới một
    thành viên nhóm `shield`. Không sở hữu thì `chmod`/`chown` ném `OSError`,
    nên bước tự sửa quyền không cứu được và phải dừng lại.

    Mô phỏng bằng cách cho `chmod`/`chown` ném lỗi thay vì cần root, để bài
    test chạy được ở mọi nơi.
    """
    backups = tmp_path / "backups"
    backups.mkdir()
    real_chmod = os.chmod
    real_chmod(backups, 0o500)

    def refuse(*args, **kwargs):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr("shield.agent.store.os.chmod", refuse)
    monkeypatch.setattr("shield.agent.store.os.chown", refuse)
    try:
        yield backups
    finally:
        real_chmod(backups, 0o700)


@pytest.mark.skipif(os.getuid() == 0, reason="root ghi được mọi nơi")
def test_an_unwritable_backup_directory_fails_closed_with_a_readable_error(
        tmp_path, unowned_backups):
    path = tmp_path / "shield.db"
    _make_v9(path)
    backups = unowned_backups
    if True:
        with pytest.raises(PermissionError) as caught:
            Store(path, allow_migration=True)
        message = str(caught.value)
        # Thông báo phải nói ra: thư mục nào, quyền hiện tại, database nào, và
        # làm gì tiếp. Một thông báo chỉ nói "unable to open database file" đã
        # khiến người đọc đi tìm database hỏng suốt một buổi.
        assert str(backups) in message
        assert "root" in message or "drwx" in message or "dr-x" in message
        assert str(path) in message
        assert "chmod" in message


@pytest.mark.skipif(os.getuid() == 0, reason="root ghi được mọi nơi")
def test_a_failed_backup_leaves_the_source_database_untouched(tmp_path, unowned_backups):
    """Không được đổi schema khi chưa sao lưu được. Đây là toàn bộ lý do bước
    sao lưu tồn tại."""
    path = tmp_path / "shield.db"
    _make_v9(path)
    before = path.read_bytes()
    with pytest.raises(PermissionError):
        Store(path, allow_migration=True)

    assert path.read_bytes() == before
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 9
    assert raw.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    raw.close()


def test_a_failed_backup_does_not_fall_back_to_another_database(tmp_path):
    """Không âm thầm đổi chỗ. Sao lưu ở một nơi mà lượt phục hồi sẽ không tìm
    tới thì tệ hơn không sao lưu, vì nó trông như đã có."""
    import inspect

    from shield.agent import store as store_module

    source = inspect.getsource(store_module.Store.backup_database)
    assert "raise PermissionError" in source
    assert "except" not in source.split("raise PermissionError")[0].split(
        "os.access")[-1], "quyền bị nuốt bằng try/except thay vì báo ra"


# --- 3+4+5. precedence của default_db_path ---


def test_the_environment_variable_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_DB", str(tmp_path / "chosen.db"))
    assert default_db_path() == tmp_path / "chosen.db"


def test_the_production_candidate_wins_when_it_is_writable(tmp_path, monkeypatch):
    monkeypatch.delenv("SHIELD_DB", raising=False)
    real_access = os.access

    def fake_access(path, mode):
        if str(path) == "/var/lib/shield":
            return True
        return real_access(path, mode)

    monkeypatch.setattr(os.path, "exists", lambda p: True
                        if str(p) == "/var/lib/shield" else os.path.isfile(p))
    monkeypatch.setattr("shield.agent.store.os.access", fake_access)
    monkeypatch.setattr("pathlib.Path.exists",
                        lambda self: True if str(self) == "/var/lib/shield"
                        else self.is_file() or self.is_dir())
    assert default_db_path() == __import__("pathlib").Path("/var/lib/shield/shield.db")


def test_the_user_database_is_used_only_when_production_is_not_writable(
        tmp_path, monkeypatch):
    monkeypatch.delenv("SHIELD_DB", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr("shield.agent.store.os.access",
                        lambda path, mode: False if str(path) == "/var/lib/shield"
                        else os.access(path, mode))
    assert default_db_path() == tmp_path / "shield" / "shield.db"


def test_the_precedence_is_deterministic(monkeypatch, tmp_path):
    """Ba lần gọi liên tiếp với cùng môi trường phải cho cùng một đường dẫn.
    Không có gì phụ thuộc thời điểm hay thứ tự."""
    monkeypatch.setenv("SHIELD_DB", str(tmp_path / "x.db"))
    assert len({default_db_path() for _ in range(3)}) == 1


# --- 6+7+8. bản sao lưu dùng được ---


def test_the_backup_is_a_readable_database_with_the_old_schema(tmp_path):
    path = tmp_path / "shield.db"
    _make_v9(path)
    Store(path, allow_migration=True).close()

    backup, = (tmp_path / "backups").glob("shield-pre-migration-v9-*.db")
    raw = sqlite3.connect(backup)
    assert raw.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 9, \
        "bản sao lưu phải là schema TRƯỚC khi đổi"
    assert raw.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    with pytest.raises(sqlite3.OperationalError):
        raw.execute("SELECT 1 FROM incident_refs")
    raw.close()


def test_no_temporary_file_is_left_behind(tmp_path):
    path = tmp_path / "shield.db"
    _make_v9(path)
    Store(path, allow_migration=True).close()
    assert list((tmp_path / "backups").glob("*.tmp")) == []


def test_a_second_start_neither_migrates_nor_backs_up_again(tmp_path):
    path = tmp_path / "shield.db"
    _make_v9(path)
    Store(path, allow_migration=True).close()
    first = sorted((tmp_path / "backups").glob("*.db"))
    assert len(first) == 1
    before = first[0].read_bytes()

    Store(path, allow_migration=True).close()
    after = sorted((tmp_path / "backups").glob("*.db"))
    assert after == first, "lượt khởi động thứ hai đã sao lưu lại"
    assert after[0].read_bytes() == before, "bản sao lưu bị ghi đè"


# --- mô hình nhóm được áp cho cả thư mục sao lưu ---


def test_the_backup_directory_inherits_the_group_permissions(tmp_path):
    """Đây là lỗi gốc. `_fix_group_permissions` áp mô hình nhóm cho thư mục
    database và các file phụ, nhưng bỏ sót `backups/`."""
    path = tmp_path / "shield.db"
    _make_v9(path)
    backups = tmp_path / "backups"
    backups.mkdir()
    os.chmod(backups, 0o700)

    Store(path, allow_migration=True).close()
    mode = stat.S_IMODE(backups.stat().st_mode)
    assert mode & stat.S_IWGRP, f"backups/ vẫn không cho nhóm ghi: {oct(mode)}"
    assert backups.stat().st_gid == tmp_path.stat().st_gid


def test_the_package_and_the_agent_agree_on_the_backup_directory_mode():
    """Hai nơi cùng tạo `backups/`: `preinst` lúc nâng cấp gói, và `Store` lúc
    agent khởi động. Nếu chúng đặt mode khác nhau thì mỗi lần cài rồi mỗi lần
    khởi động sẽ đè lẫn nhau, và quyền của thư mục phụ thuộc vào cái nào chạy
    sau cùng."""
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parent.parent
    preinst = (root / "packaging" / "debian" / "preinst").read_text(encoding="utf-8")
    store_source = (root / "shield" / "agent" / "store.py").read_text(encoding="utf-8")
    assert 'install -d -m 1770 "$BACKUP_DIR"' in preinst
    assert "os.chmod(directory, 0o1770)" in store_source
    assert 'install -d -m 700' not in preinst, \
        "preinst lại đặt 700 — mỗi lần nâng cấp sẽ tái tạo lỗi quyền"


def test_the_backup_directory_keeps_the_sticky_bit(tmp_path):
    """Mở quyền ghi cho nhóm mà không có sticky nghĩa là một thành viên nhóm
    xoá được bản sao lưu của người khác."""
    path = tmp_path / "shield.db"
    _make_v9(path)
    Store(path, allow_migration=True).close()
    mode = stat.S_IMODE((tmp_path / "backups").stat().st_mode)
    assert mode & stat.S_ISVTX, f"thiếu sticky bit: {oct(mode)}"
    assert mode & stat.S_IWGRP
