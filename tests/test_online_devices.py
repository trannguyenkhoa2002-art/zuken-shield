"""Con số "N online" phải tra ngược được ra đúng N thiết bị.

Một con số không tra ngược được thì không dùng để làm gì: nhìn thấy "8 online"
mà không biết 8 cái đó là ai thì không thể biết cái thứ 9 vừa biến mất là cái
nào, hay cái lạ vừa xuất hiện là cái nào.
"""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from shield.agent.store import Store  # noqa: E402
from shield.ui import i18n  # noqa: E402


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def store_with_devices(tmp_path):
    store = Store(tmp_path / "shield.db")
    now = time.time()
    # 3 máy vừa thấy, 2 máy im lặng từ lâu.
    for index in range(3):
        store.upsert_device(f"aa:bb:cc:00:00:0{index}", f"192.168.1.{index + 10}", "TestCorp")
    for index in range(2):
        mac = f"dd:ee:ff:00:00:0{index}"
        store.upsert_device(mac, f"192.168.1.{index + 50}", "OldCorp")
        # Cập nhật CẢ HAI bảng, đúng như đường ghi thật: `devices` là sổ quan
        # sát thô, `device_observations` là lớp danh tính.
        store.conn.execute("UPDATE devices SET last_seen=? WHERE mac=?", (now - 7200, mac))
        store.conn.execute(
            "UPDATE device_observations SET last_seen=? WHERE mac=?", (now - 7200, mac))
    store.conn.commit()
    yield store
    store.close()


def _overview(store):
    from shield.ui.__main__ import OverviewTab

    tab = OverviewTab(store, None)
    tab.refresh()
    return tab


@pytest.mark.parametrize("language", ["vi", "en"])
def test_the_count_and_the_list_always_agree(app, store_with_devices, language):
    i18n.set_lang(language)
    tab = _overview(store_with_devices)
    assert tab.online_table.rowCount() == 3, "bảng không liệt kê đúng số máy đang online"
    # Con số trong ô phải là chính con số đó, không phải một phép đếm khác.
    assert tab.val_devices.text().startswith("3 "), tab.val_devices.text()


@pytest.mark.parametrize("language", ["vi", "en"])
def test_the_word_online_sits_next_to_the_number(app, store_with_devices, language):
    """"8 / 101" một mình không nói được 8 là cái gì trong 101."""
    i18n.set_lang(language)
    tab = _overview(store_with_devices)
    assert "online" in tab.val_devices.text().lower()
    assert "/ 5" in tab.val_devices.text()


@pytest.mark.parametrize("language", ["vi", "en"])
def test_every_listed_device_is_identifiable(app, store_with_devices, language):
    """Liệt kê mà không có IP/MAC thì vẫn không tra ra được là máy nào."""
    i18n.set_lang(language)
    tab = _overview(store_with_devices)
    for row in range(tab.online_table.rowCount()):
        assert tab.online_table.item(row, 0).text().lower() == "online"
        assert tab.online_table.item(row, 2).text().startswith("192.168."), "thiếu IP"
        assert ":" in tab.online_table.item(row, 3).text(), "thiếu MAC"


def test_offline_devices_are_not_listed(app, store_with_devices):
    i18n.set_lang("en")
    tab = _overview(store_with_devices)
    listed = {tab.online_table.item(row, 3).text() for row in range(tab.online_table.rowCount())}
    assert not any(mac.startswith("dd:ee:ff") for mac in listed)


def test_an_empty_list_explains_itself(app, tmp_path):
    """Bảng rỗng phải nói vì sao rỗng, không để người dùng tự đoán."""
    i18n.set_lang("en")
    tab = _overview(Store(tmp_path / "empty.db"))
    assert tab.online_table.rowCount() == 0
    assert tab.online_note.text().strip(), "bảng rỗng mà không giải thích gì"
    assert "event rate" in tab.online_note.text()


@pytest.mark.parametrize("language", ["vi", "en"])
def test_the_devices_tab_says_online_in_words(app, store_with_devices, language):
    """Chỉ tô màu là mất sạch thông tin với người mù màu và ảnh đen trắng."""
    from shield.ui.__main__ import DevicesTab

    i18n.set_lang(language)
    tab = DevicesTab(store_with_devices, None)
    tab.refresh()
    assert tab.table.columnCount() >= 10
    texts = [tab.table.item(row, 0).text().lower() for row in range(tab.table.rowCount())]
    assert texts.count("online") == 3
    assert texts.count("offline") == 2
    # Máy đang online phải nằm trên đầu — thứ đang hoạt động mới là thứ cần nhìn.
    assert texts[:3] == ["online"] * 3


def test_a_rebuilt_identity_keeps_the_real_timestamps(tmp_path):
    """Dựng lại danh tính không được đóng dấu "bây giờ" lên dữ liệu cũ.

    Bản trước gán `time.time()` cho mọi thiết bị được backfill, nên một máy tắt
    từ tuần trước hiện lên như đang online — và `first_seen` mất luôn. Với công
    cụ điều tra thì "thấy lần đầu / lần cuối" chính là dữ kiện người ta dựa vào.
    """
    long_ago = time.time() - 8 * 86400
    path = tmp_path / "old.db"
    store = Store(path)
    store.conn.execute(
        "INSERT INTO devices(mac,ip,vendor,hostname,first_seen,last_seen) "
        "VALUES('11:22:33:44:55:66','10.0.0.5','OldCorp','',?,?)",
        (long_ago, long_ago),
    )
    store.conn.commit()
    store.close()

    # Lượt mở tiếp theo sẽ dựng danh tính cho thiết bị đó. Backfill là một
    # hoạt động migration, nên chỉ chạy khi được cho phép tường minh.
    store = Store(path, allow_migration=True)
    try:
        rows = store.conn.execute(
            "SELECT first_seen, last_seen FROM device_observations "
            "WHERE mac='11:22:33:44:55:66'"
        ).fetchall()
        assert rows, "không dựng được danh tính"
        first_seen, last_seen = rows[0]
        assert abs(last_seen - long_ago) < 5, f"last_seen bị đóng dấu lại: {last_seen}"
        assert abs(first_seen - long_ago) < 5, f"first_seen bị đóng dấu lại: {first_seen}"
    finally:
        store.close()


def test_old_fabricated_timestamps_are_repaired(tmp_path):
    """Dữ liệu đã bị đóng dấu sai từ bản trước phải được sửa lại."""
    long_ago = time.time() - 8 * 86400
    path = tmp_path / "damaged.db"
    store = Store(path)
    store.upsert_device("11:22:33:44:55:66", "10.0.0.5", "OldCorp")
    # Mô phỏng đúng thiệt hại: devices giữ mốc thật, observations bị đóng dấu nay.
    store.conn.execute(
        "UPDATE devices SET first_seen=?, last_seen=? WHERE mac='11:22:33:44:55:66'",
        (long_ago, long_ago),
    )
    store.conn.execute(
        "UPDATE device_observations SET observation_count=1, first_seen=?, last_seen=?",
        (time.time(), time.time()),
    )
    store.conn.commit()

    store._repair_backfilled_timestamps()
    first_seen, last_seen = store.conn.execute(
        "SELECT first_seen, last_seen FROM device_observations"
    ).fetchone()
    assert abs(last_seen - long_ago) < 5, "chưa sửa lại last_seen"
    assert abs(first_seen - long_ago) < 5, "chưa sửa lại first_seen"
    store.close()


def test_the_repair_never_moves_a_recent_sighting_backwards(tmp_path):
    """Chỉ sửa dấu vết của lượt backfill, không đụng vào quan sát thật."""
    path = tmp_path / "fresh.db"
    store = Store(path)
    store.upsert_device("11:22:33:44:55:66", "10.0.0.5", "NewCorp")
    before = store.conn.execute("SELECT last_seen FROM device_observations").fetchone()[0]
    store._repair_backfilled_timestamps()
    after = store.conn.execute("SELECT last_seen FROM device_observations").fetchone()[0]
    assert after == before
    store.close()
