"""Thêm một loại hành vi MỚI vào máy đang chạy không được gây trận cảnh báo.

Đây là lỗi A2 lặp lại qua một lối vào khác. Lần A2, `process_started` đổi cách
dựng khoá và 640 khoá đã học thành vô dụng — ~200 cảnh báo/giờ trên máy thật.
Lối vào ở đây khác: `reconcile_behavior_key_formats` phân biệt "chưa lưu +
phiên bản ≤ 1" (ghi nhận rồi đi tiếp) với "chưa lưu + phiên bản ≥ 2" (học
lại), nhưng loại MỚI luôn bắt đầu ở phiên bản 1 — nên nó rơi vào nhánh "đi
tiếp". Cộng với cửa sổ học toàn cục đã đóng (7 ngày), mọi khoá đầu tiên của
loại mới đều bắn cảnh báo NGAY.

Đo trên máy thật trước khi sửa: cửa sổ toàn cục đã đóng 1,9 ngày, và mỗi khoá
mới sinh BA cảnh báo — `minimum_observations = 3` đếm `previous` TRƯỚC khi
tăng, nên previous = 0, 1, 2 đều báo.
"""

from __future__ import annotations

import time

import pytest

from shield.agent.store import Store
from shield.common.models import Event
from shield.security.anomaly import (
    BEHAVIOR_KEY_FORMATS,
    DEVICE_KINDS,
    KEY_VALUE_BUILDERS,
    LOGIN_KINDS,
    OBSERVED_KINDS,
    LocalBaselineDetector,
    behavior_key,
)

MOT_LOAI_MOI = "synthetic_probe_kind"


def _event(kind, **data):
    data.setdefault("uid", 0)
    return Event(ts=time.time(), source="test", kind=kind, data=data,
                 origin="local", trust="authenticated")


def _may_da_chay_lau(tmp_path, ngay=30.0):
    """Một máy đã chạy lâu: cửa sổ học toàn cục đã đóng, đã có baseline."""
    store = Store(tmp_path / "shield.db")
    xua = time.time() - ngay * 86400
    store.conn.execute(
        "INSERT OR REPLACE INTO baseline(key,value,set_ts) VALUES('anomaly_learning_started',?,?)",
        (str(xua), xua))
    store.conn.commit()
    store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    det = LocalBaselineDetector(store)
    for i in range(5):
        for _ in range(4):
            det.handle_event(_event("process_exec", exe=f"/usr/bin/tool{i}"))
    return store, det


def _dem(store, kind=None):
    if kind is None:
        return store.conn.execute("SELECT COUNT(*) FROM behavior_baselines").fetchone()[0]
    return store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind=?", (kind,)).fetchone()[0]


# --- A. đăng ký loại mới trên máy đang chạy ---


def test_a_new_kind_on_a_running_machine_opens_a_scoped_relearn_window(tmp_path):
    store, _ = _may_da_chay_lau(tmp_path)
    truoc = _dem(store)

    changed = store.reconcile_behavior_key_formats({**BEHAVIOR_KEY_FORMATS, MOT_LOAI_MOI: 1})

    assert [c["kind"] for c in changed] == [MOT_LOAI_MOI]
    assert changed[0]["deleted_keys"] == 0, "loại mới thì không có gì để xoá"
    assert store._relearn_until_for(MOT_LOAI_MOI) > time.time()
    assert _dem(store) == truoc, "baseline của loại khác phải còn nguyên"
    assert store._relearn_until_for("process_exec") == 0, "không được đụng loại khác"


def test_a_new_kind_produces_no_immediate_anomaly(tmp_path):
    store, det = _may_da_chay_lau(tmp_path)
    store.reconcile_behavior_key_formats({**BEHAVIOR_KEY_FORMATS, MOT_LOAI_MOI: 1})

    canh_bao = 0
    for i in range(40):
        canh_bao += len(det._check(_event(MOT_LOAI_MOI), f"{MOT_LOAI_MOI}|0|1|khoa{i}",
                                   "ANOMALY_NEW_BEHAVIOR", "t", "d"))
    assert canh_bao == 0, f"{canh_bao} cảnh báo — đúng trận cảnh báo mà bản sửa này để chặn"
    assert det.suppressed_by_relearn.get(MOT_LOAI_MOI) == 40, \
        "nén mà không đếm là nén trong im lặng"


def test_the_old_baselines_are_untouched(tmp_path):
    store, _ = _may_da_chay_lau(tmp_path)
    truoc = {r[0]: r[1] for r in store.conn.execute(
        "SELECT behavior_key, observation_count FROM behavior_baselines")}
    store.reconcile_behavior_key_formats({**BEHAVIOR_KEY_FORMATS, MOT_LOAI_MOI: 1})
    sau = {r[0]: r[1] for r in store.conn.execute(
        "SELECT behavior_key, observation_count FROM behavior_baselines")}
    assert sau == truoc


# --- cài mới thì không được sinh trạng thái thừa ---


def test_a_fresh_install_creates_no_relearn_state(tmp_path):
    """Cài mới đã có cửa sổ học toàn cục; mở thêm cửa sổ học lại cho từng loại
    là nén cảnh báo lâu hơn cần thiết mà không ai yêu cầu."""
    store = Store(tmp_path / "shield.db")
    changed = store.reconcile_behavior_key_formats(
        {k: v for k, v in BEHAVIOR_KEY_FORMATS.items() if v <= 1})
    assert changed == []
    thua = store.conn.execute(
        "SELECT COUNT(*) FROM baseline WHERE key LIKE 'behavior_relearn%'").fetchone()[0]
    assert thua == 0


def test_the_a2_relearn_still_fires_on_a_pre_versioning_machine(tmp_path):
    """A2 KHÔNG được hồi quy: máy có baseline từ trước cơ chế đánh số, loại đã
    ở phiên bản ≥ 2 thì không biết nó học bằng định dạng nào — phải học lại."""
    store = Store(tmp_path / "shield.db")
    det = LocalBaselineDetector(store)
    for i in range(3):
        det.handle_event(_event("process_started", exe=f"/usr/bin/x{i}"))
    assert _dem(store, "process_started") == 3

    changed = store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    assert [c["kind"] for c in changed] == ["process_started"]
    assert changed[0]["deleted_keys"] == 3
    assert _dem(store, "process_started") == 0
    assert _dem(store, "process_exec") == 0


# --- idempotent, và sống qua khởi động lại ---


def test_a_second_reconcile_changes_nothing(tmp_path):
    store, _ = _may_da_chay_lau(tmp_path)
    formats = {**BEHAVIOR_KEY_FORMATS, MOT_LOAI_MOI: 1}
    store.reconcile_behavior_key_formats(formats)
    moc = store._relearn_until_for(MOT_LOAI_MOI)

    assert store.reconcile_behavior_key_formats(formats) == []
    store._relearn_cache = None
    assert store._relearn_until_for(MOT_LOAI_MOI) == moc, \
        "phiên bản không đổi thì KHÔNG được gia hạn cửa sổ học lại"


def test_a_restart_during_relearn_keeps_the_window(tmp_path):
    store, _ = _may_da_chay_lau(tmp_path)
    formats = {**BEHAVIOR_KEY_FORMATS, MOT_LOAI_MOI: 1}
    store.reconcile_behavior_key_formats(formats)
    moc = store._relearn_until_for(MOT_LOAI_MOI)
    store.close() if hasattr(store, "close") else None

    lai = Store(tmp_path / "shield.db")
    assert lai.reconcile_behavior_key_formats(formats) == []
    assert lai._relearn_until_for(MOT_LOAI_MOI) == moc


def test_anomalies_resume_once_the_relearn_window_expires(tmp_path):
    """Nén vĩnh viễn là tắt detector. Cửa sổ phải hết hạn."""
    store, det = _may_da_chay_lau(tmp_path)
    store.reconcile_behavior_key_formats({**BEHAVIOR_KEY_FORMATS, MOT_LOAI_MOI: 1})

    het = time.time() - 1
    store.conn.execute("UPDATE baseline SET value=? WHERE key=?",
                       (str(het), store._RELEARN_KEY + MOT_LOAI_MOI))
    store.conn.commit()
    store._relearn_cache = None

    canh_bao = len(det._check(_event(MOT_LOAI_MOI), f"{MOT_LOAI_MOI}|0|1|sau_khi_het",
                              "ANOMALY_NEW_BEHAVIOR", "t", "d"))
    assert canh_bao == 1


# --- B. không còn nhánh bắt tất cả ---


def test_an_unhandled_kind_never_produces_an_empty_key():
    """Trước bản sửa: `'socket_connect|1000|1|'` — mọi event gộp một khoá rỗng,
    không lỗi, không dấu hiệu."""
    assert behavior_key(_event("socket_connect", uid=1000, remote_ip="8.8.8.8")) is None


def test_an_unhandled_kind_neither_learns_nor_alerts(tmp_path):
    store, det = _may_da_chay_lau(tmp_path)
    truoc = _dem(store)
    import shield.security.anomaly as A
    goc = A.OBSERVED_KINDS
    A.OBSERVED_KINDS = goc | {"socket_connect"}
    try:
        assert det.handle_event(_event("socket_connect", uid=1000)) == []
    finally:
        A.OBSERVED_KINDS = goc
    assert _dem(store) == truoc, "không được học một khoá bịa ra"


@pytest.mark.parametrize("kind", sorted(OBSERVED_KINDS))
def test_every_observed_kind_has_an_explicit_key_builder(kind):
    assert kind in KEY_VALUE_BUILDERS, (
        f"{kind!r} nằm trong OBSERVED_KINDS nhưng không có hàm dựng khoá — "
        "trước đây nhánh else bắt tất cả sẽ nuốt trường hợp này")


def test_the_key_builder_table_has_no_catch_all():
    """Bất biến chống hồi quy: `behavior_key` không được có `else` bắt tất cả."""
    import ast
    import inspect

    import shield.security.anomaly as A

    cay = ast.parse(inspect.getsource(A.behavior_key))
    for nut in ast.walk(cay):
        if isinstance(nut, ast.If):
            assert not nut.orelse or isinstance(nut.orelse[0], ast.If), \
                "behavior_key có nhánh else — chính là lỗi bản sửa này gỡ bỏ"


def test_behavior_key_formats_covers_every_versioned_kind():
    thieu = (OBSERVED_KINDS | DEVICE_KINDS | LOGIN_KINDS) - set(BEHAVIOR_KEY_FORMATS)
    assert not thieu, f"thiếu phiên bản định dạng cho: {sorted(thieu)}"
