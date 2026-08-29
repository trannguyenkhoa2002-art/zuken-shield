"""Test phần né tránh khẩn cấp — chỉ hàm thuần (sinh MAC, ràng buộc chu kỳ),
không gọi nmcli/ip thật."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from shield.agent import evasion
from shield.agent.store import Store

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def test_random_mac_format():
    mac = evasion.random_mac()
    assert _MAC_RE.match(mac)


def test_random_mac_is_unicast_and_locally_administered():
    """Bit thứ nhất byte đầu = 0 (unicast), bit thứ hai = 1 (tự đặt) — không
    trùng dải MAC thật của bất kỳ hãng nào, không giả mạo thiết bị ai khác."""
    for _ in range(200):
        mac = evasion.random_mac()
        first_byte = int(mac.split(":")[0], 16)
        assert first_byte & 0b1 == 0, f"MAC không phải unicast: {mac}"
        assert first_byte & 0b10 == 0b10, f"MAC không phải locally-administered: {mac}"


def test_random_mac_varies():
    macs = {evasion.random_mac() for _ in range(50)}
    assert len(macs) > 40  # xác suất trùng cực thấp, chỉ chặn bug sinh hằng số


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(path=tmp_path / "test.db")
    yield s
    s.close()


def test_evasion_interval_defaults_when_unset(store: Store):
    from shield.agent.__main__ import evasion_interval, EVASION_DEFAULT_INTERVAL_S

    assert evasion_interval(store) == EVASION_DEFAULT_INTERVAL_S


def test_should_restore_on_boot_only_when_dirty_and_disabled(store: Store):
    from shield.agent.__main__ import (
        evasion_should_restore_on_boot,
        EVASION_DIRTY_KEY,
        EVASION_ENABLED_KEY,
    )

    # Sạch, tắt -> không cần khôi phục.
    assert evasion_should_restore_on_boot(store, "wlo1") is False

    # Bẩn + đã tắt (đúng kịch bản crash) -> cần khôi phục.
    store.set_baseline(EVASION_DIRTY_KEY, "1")
    assert evasion_should_restore_on_boot(store, "wlo1") is True

    # Bẩn nhưng vẫn đang bật -> loop tự xoay tiếp, KHÔNG khôi phục lúc boot.
    store.set_baseline(EVASION_ENABLED_KEY, "1")
    assert evasion_should_restore_on_boot(store, "wlo1") is False

    # Không có interface -> không làm gì.
    store.set_baseline(EVASION_ENABLED_KEY, "0")
    assert evasion_should_restore_on_boot(store, None) is False


def test_evasion_interval_clamped_to_bounds(store: Store):
    from shield.agent.__main__ import (
        evasion_interval,
        EVASION_MIN_INTERVAL_S,
        EVASION_MAX_INTERVAL_S,
        EVASION_INTERVAL_KEY,
    )

    store.set_baseline(EVASION_INTERVAL_KEY, "1")
    assert evasion_interval(store) == EVASION_MIN_INTERVAL_S

    store.set_baseline(EVASION_INTERVAL_KEY, "99999")
    assert evasion_interval(store) == EVASION_MAX_INTERVAL_S

    store.set_baseline(EVASION_INTERVAL_KEY, "not-a-number")
    from shield.agent.__main__ import EVASION_DEFAULT_INTERVAL_S

    assert evasion_interval(store) == EVASION_DEFAULT_INTERVAL_S

    store.set_baseline(EVASION_INTERVAL_KEY, "120")
    assert evasion_interval(store) == 120
