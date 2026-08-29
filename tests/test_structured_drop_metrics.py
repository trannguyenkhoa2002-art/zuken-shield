"""Trường đọc-được-bằng-máy phải nói cùng một điều với câu đọc-được-bằng-mắt.

Đo trên máy thật: `kernel_telemetry.file_write` có
`detail = "… — đã bỏ 13992 event do giới hạn tốc độ"` trong khi
`dropped_events = 0`. Bất cứ thứ gì đọc cột đó — cảnh báo, bảng điều khiển,
export — đều thấy "không mất gì". Đây là lần thứ năm cùng một lớp lỗi: agent
sinh ra một CÂU thay vì sinh ra DỮ LIỆU.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from shield.agent.collectors.kernel import PROBES, ProbeSupport, _report
from shield.agent.collectors.ratelimit import RateLimiter
from shield.agent.store import Store


class _Store:
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    def set_collector_health(self, component, backend, healthy, detail, **kwargs) -> None:
        self.rows[component] = {"healthy": healthy, "detail": detail, **kwargs}


def _support():
    return ProbeSupport(supported=dict.fromkeys(PROBES, "ok"))


# --- trần tốc độ -> trường có cấu trúc ---


def test_rate_limit_drops_reach_the_structured_field():
    store = _Store()
    _report(store, _support(), True, "chạy", {"file_write": 13992})
    hang = store.rows["kernel_telemetry.file_write"]
    assert hang["dropped_events"] == 13992
    assert "13992" in hang["detail"], "câu văn và con số phải khớp nhau"


def test_a_kind_that_dropped_nothing_reports_zero():
    store = _Store()
    _report(store, _support(), True, "chạy", {"file_write": 5})
    assert store.rows["kernel_telemetry.process_exec"]["dropped_events"] == 0


def test_the_startup_report_resets_the_counter_rather_than_preserving_it():
    """Bộ đếm của RateLimiter sống theo TIẾN TRÌNH. Giữ tổng của lần chạy
    trước sẽ khiến con số đi giật lùi ngay khi tiến trình mới bỏ event đầu
    tiên — một con số cộng dồn mà giảm được thì không ai đọc nó nữa."""
    store = _Store()
    _report(store, _support(), True, "khởi động", {})
    assert all(store.rows[f"kernel_telemetry.{k}"]["dropped_events"] == 0 for k in PROBES)


def test_an_unknown_count_preserves_the_previous_value():
    """None nghĩa là "lượt này không biết", KHÔNG phải "bằng không"."""
    store = _Store()
    _report(store, _support(), True, "chạy")
    assert store.rows["kernel_telemetry.file_write"]["dropped_events"] is None


def test_drops_never_mark_the_probe_unhealthy():
    """Chạm trần trong một chớp lưu lượng không có nghĩa là probe đã tắt. Đo
    trên máy thật: `file_write` chạm trần 142/18.454 giây có hoạt động."""
    store = _Store()
    _report(store, _support(), True, "chạy", {"file_write": 13992})
    assert store.rows["kernel_telemetry.file_write"]["healthy"] is True


def test_a_historical_total_does_not_make_the_collector_bad():
    """Cộng dồn KHÁC với đang mất. `losing_data_since_last_check` trả lời câu
    thứ hai, và chỉ câu thứ hai mới quyết định healthy — nếu không, ba gói bị
    bỏ hôm qua sẽ giữ collector ở trạng thái BAD vĩnh viễn."""
    limiter = RateLimiter({"arp": 1})
    limiter.allow("arp", 1000.0)
    limiter.allow("arp", 1000.0)          # bị bỏ
    assert limiter.total_dropped() == 1
    assert limiter.losing_data_since_last_check() is True
    assert limiter.losing_data_since_last_check() is False, "không có lượt bỏ mới"
    assert limiter.total_dropped() == 1, "tổng cộng dồn không được reset theo"


# --- các loại mất mát KHÔNG được trộn vào nhau ---


def test_each_component_owns_its_own_row(tmp_path):
    """Không cộng trùng: mỗi thành phần là một HÀNG riêng, nên số của bus và
    số của collector không bao giờ chồng lên nhau."""
    store = Store(tmp_path / "s.db")
    store.set_collector_health("event_bus", "asyncio-queue", False, "đầy", dropped_events=7)
    store.set_collector_health("kernel_telemetry.file_write", "ebpf", True, "chạy",
                               dropped_events=13992)
    rows = {r["component"]: r["dropped_events"] for r in store.collector_health()}
    assert rows["event_bus"] == 7
    assert rows["kernel_telemetry.file_write"] == 13992


def test_viewer_evictions_are_not_telemetry_loss():
    """Người xem đọc chậm là giới hạn MÀN HÌNH: event vẫn nằm nguyên trong
    database và tra lại được qua Expert Evidence. Cộng nó vào con số mất
    telemetry sẽ biến một giao diện đang cuộn chậm thành một Shield đang mù."""
    import ast
    import inspect

    import shield.agent.__main__ as M

    nguon = inspect.getsource(M)
    i = nguon.index('"evidence_feed", "bounded-queue"')
    doan = nguon[i:i + 700]
    assert "dropped_events=0" in doan, \
        "evidence_feed phải ghi 0 một cách TƯỜNG MINH, để không ai 'sửa' nó sau này"


def test_aggregator_overflow_is_not_added_to_rate_limit_drops():
    """Tràn trần khoá là mất một KHOÁ gộp, không phải một event. Cộng chung
    hai đơn vị khác nhau cho ra một con số không còn nghĩa gì."""
    import inspect

    import shield.agent.collectors.conn_watch as C

    nguon = inspect.getsource(C)
    i = nguon.index('"conn_watch", "scapy+aggregate"')
    doan = nguon[i:i + 400]
    assert "dropped_events=limiter.total_dropped()" in doan
    assert "overflow" not in doan.split("dropped_events=")[1][:120], \
        "số tràn khoá không được cộng vào số bỏ do trần tốc độ"


def test_the_detail_string_and_the_counter_never_disagree():
    """Bất biến của cả bản sửa này: nếu câu văn nói có bỏ thì con số phải > 0."""
    for so_bo in (0, 1, 13992):
        store = _Store()
        _report(store, _support(), True, "chạy", {"file_write": so_bo} if so_bo else {})
        hang = store.rows["kernel_telemetry.file_write"]
        noi_co_bo = "đã bỏ" in hang["detail"]
        assert noi_co_bo == (hang["dropped_events"] > 0), (so_bo, hang)
