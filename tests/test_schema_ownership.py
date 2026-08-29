"""Chỉ MỘT tiến trình được đổi schema (KE-HOACH-SHIELD-2.0.md mục 1.1).

Cùng một lỗi đã xảy ra hai lần:

- 1.1: guardian mở Store chế độ ghi trong lúc agent migrate 143 MB ->
  `sqlite3.OperationalError: disk I/O error`.
- 2.0: giao diện mở `Store()` với quyền migrate mặc định trong lúc agent migrate
  204 MB v4 -> v5 -> `sqlite3.OperationalError: database is locked` ngay lúc
  người dùng bấm mở app, ngay sau khi nâng cấp.

Lần thứ nhất được sửa bằng cách sửa MỘT chỗ gọi. Lần này sửa bằng cách đổi mặc
định: `allow_migration` mặc định False, và chỉ agent viết `True` ra. Một mặc
định "được phép" nghĩa là mọi chỗ gọi mới tự động có quyền đổi schema.
"""

from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

from shield.agent.store import SCHEMA_VERSION, Store

ROOT = Path(__file__).resolve().parent.parent


def _store_calls(path: Path) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "Store"]


def _allows_migration(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "allow_migration":
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False


def test_migration_is_off_by_default():
    """Mặc định phải là KHÔNG. Một mặc định 'được phép' nghĩa là mọi chỗ gọi
    mới tự động có quyền đổi schema của một database 204 MB."""
    import inspect

    signature = inspect.signature(Store.__init__)
    assert signature.parameters["allow_migration"].default is False


def test_only_the_agent_asks_for_migration_rights():
    """Đúng một tiến trình được đổi schema. Nếu danh sách này dài ra, ai đó
    vừa mở lại đúng cánh cửa đã sập hai lần."""
    allowed = {"shield/agent/__main__.py"}
    offenders = []
    for path in sorted(ROOT.glob("shield/**/*.py")):
        relative = str(path.relative_to(ROOT))
        if any(_allows_migration(call) for call in _store_calls(path)):
            if relative not in allowed:
                offenders.append(relative)
    assert offenders == [], f"những chỗ này tự cho mình quyền migrate: {offenders}"


def test_the_ui_never_migrates():
    source = (ROOT / "shield/ui/__main__.py").read_text(encoding="utf-8")
    assert "allow_migration=False" in source
    for call in _store_calls(ROOT / "shield/ui/__main__.py"):
        assert not _allows_migration(call)


def test_the_guardian_never_migrates():
    for call in _store_calls(ROOT / "shield/guardian/__main__.py"):
        assert not _allows_migration(call)


# --- hành vi ---


def test_a_brand_new_database_is_always_created_in_full(tmp_path):
    """Cấm migrate KHÔNG được biến thành 'để lại một file rỗng'.

    Điều kiện phải là 'database đã tồn tại', không phải 'không được migrate'
    một mình — nếu không, mọi tiến trình phụ chạy trước agent sẽ tạo ra một
    database không có bảng nào.
    """
    store = Store(tmp_path / "fresh.db", allow_migration=False)
    try:
        tables = {row[0] for row in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"events", "alerts", "graph_entities", "graph_edges"} <= tables
        assert store.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    finally:
        store.close()


def test_an_existing_outdated_database_is_left_untouched(tmp_path):
    path = tmp_path / "old.db"
    Store(path, allow_migration=True).close()
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version=3")
    conn.commit()
    conn.close()

    store = Store(path, allow_migration=False)
    try:
        assert store.schema_outdated is True
        assert store.conn.execute("PRAGMA user_version").fetchone()[0] == 3
    finally:
        store.close()
    assert not list((tmp_path / "backups").glob("*.db")), \
        "đã sao lưu 204 MB từ một tiến trình không được phép migrate"


def test_a_reader_does_not_back_up_the_database(tmp_path):
    """Sao lưu trước migration là việc của agent. Hai tiến trình cùng sao lưu
    một file 204 MB là hai lần ghi đĩa và một lần tranh khoá."""
    path = tmp_path / "shield.db"
    Store(path, allow_migration=True).close()
    backups_before = list((tmp_path / "backups").glob("*.db"))
    Store(path, allow_migration=False).close()
    assert list((tmp_path / "backups").glob("*.db")) == backups_before


def test_the_ui_helper_retries_instead_of_crashing():
    """Agent giữ khoá ghi lúc migrate là trạng thái tạm và bình thường. Giao
    diện sập vì nó thì người dùng thấy traceback ngay sau khi nâng cấp — trông
    y hệt một bản cài hỏng."""
    source = (ROOT / "shield/ui/__main__.py").read_text(encoding="utf-8")
    index = source.index("def _open_store_for_ui")
    block = source[index:index + 1200]
    assert "sqlite3.OperationalError" in block
    assert "for attempt in range" in block
