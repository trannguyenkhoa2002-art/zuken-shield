"""Cách ly endpoint: xem trước tác động + dead-man switch (mục B8)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from shield.security.response import (
    DeadManSwitch,
    IsolationPlan,
    Quarantine,
    ResponseExecutor,
)


# --- xem trước tác động ---


def test_the_preview_names_services_not_port_numbers():
    """"deny non-management traffic" không nói cho ai biết họ sắp mất SSH."""
    plan = IsolationPlan.create("192.168.1.10", ttl_s=300)
    result = plan.preview()
    assert result.ok is True
    for service in ("SSH", "DNS", "Web"):
        assert service in result.message


def test_preserving_dns_is_reflected_in_the_impact_list():
    plan = IsolationPlan.create("192.168.1.10", ttl_s=300, preserve_dns=True)
    dns = next(item for item in plan.impact() if item["service"] == "DNS")
    assert dns["affected"] is False
    assert "SSH" in plan.preview().message


def test_an_unsafe_plan_is_refused():
    for ip, ttl in (("0.0.0.0", 300), ("224.0.0.1", 300), ("192.168.1.1", 5), ("192.168.1.1", 99999)):
        with pytest.raises(ValueError):
            IsolationPlan.create(ip, ttl_s=ttl)


# --- dead-man switch ---


def test_isolation_is_refused_without_a_dead_man_switch(tmp_path):
    """Cách ly một máy rồi mất khả năng gỡ là hỏng nặng hơn thứ đang phòng chống."""
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=None)
    result = asyncio.run(executor._dispatch("isolate_endpoint",
                                       {"management_ip": "192.168.1.10", "ttl_s": 300},
                                       dry_run=False))
    assert result.ok is False
    assert "dead-man" in result.message


def test_isolation_arms_the_switch_and_returns_a_rollback_id(tmp_path):
    """Test này TỪNG hợp thức hoá một lời nói dối.

    Bản cũ không truyền privileged_client mà vẫn assert ok=True — nghĩa là nó
    khẳng định "cách ly thành công" trong đúng tình huống không có cách nào áp
    được luật firewall. Nó xanh suốt vì hành vi sai và kỳ vọng sai khớp nhau.
    Giờ phải có helper thật (giả lập) thì mới được coi là cách ly.
    """
    class _Helper:
        async def call(self, action, params):
            return {"ok": True, "action": action, "message": "verified"}

    switch = DeadManSwitch(tmp_path / "deadman.json")
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=switch,
                                privileged_client=_Helper())
    result = asyncio.run(executor._dispatch("isolate_endpoint",
                                       {"management_ip": "192.168.1.10", "ttl_s": 300},
                                       dry_run=False))
    assert result.ok is True
    assert result.rollback_id and result.rollback_id.startswith("isolation:")
    assert "192.168.1.10" in switch.armed()


def test_an_unrenewed_isolation_expires(tmp_path):
    """Kịch bản tệ nhất: agent cách ly máy rồi chính agent chết. Không có
    công tắc này thì máy nằm ngoài mạng vĩnh viễn."""
    clock = [1000.0]
    switch = DeadManSwitch(tmp_path / "deadman.json", clock=lambda: clock[0])
    switch.arm("10.0.0.5", ttl_s=300)
    assert switch.expired() == []
    clock[0] += 299
    assert switch.expired() == []
    clock[0] += 2
    assert switch.expired() == ["10.0.0.5"]


def test_renewing_pushes_the_deadline_out(tmp_path):
    clock = [1000.0]
    switch = DeadManSwitch(tmp_path / "deadman.json", clock=lambda: clock[0])
    switch.arm("10.0.0.5", ttl_s=300)
    clock[0] += 250
    assert switch.renew("10.0.0.5", ttl_s=300) is True
    clock[0] += 100
    assert switch.expired() == []


def test_renewing_something_that_was_never_armed_does_nothing(tmp_path):
    switch = DeadManSwitch(tmp_path / "deadman.json")
    assert switch.renew("10.0.0.5", ttl_s=300) is False
    assert switch.armed() == {}


def test_disarming_stops_the_countdown(tmp_path):
    clock = [1000.0]
    switch = DeadManSwitch(tmp_path / "deadman.json", clock=lambda: clock[0])
    switch.arm("10.0.0.5", ttl_s=60)
    assert switch.disarm("10.0.0.5") is True
    clock[0] += 600
    assert switch.expired() == []


def test_the_deadline_is_written_to_disk(tmp_path):
    """Agent chết rồi khởi động lại vẫn phải biết mình đang nợ một lần gỡ."""
    state = tmp_path / "deadman.json"
    DeadManSwitch(state).arm("10.0.0.5", ttl_s=300)
    assert state.exists() and "10.0.0.5" in state.read_text()


def test_a_read_only_state_directory_does_not_break_isolation(tmp_path):
    """Không ghi được state là chuyện nhỏ; không gỡ được cách ly mới là chuyện lớn."""
    switch = DeadManSwitch(Path("/proc/không-ghi-được/deadman.json"))
    switch.arm("10.0.0.5", ttl_s=1)
    assert "10.0.0.5" in switch.armed()


def test_a_dry_run_never_arms_anything(tmp_path):
    switch = DeadManSwitch(tmp_path / "deadman.json")
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=switch)
    result = asyncio.run(executor._dispatch("isolate_endpoint",
                                       {"management_ip": "192.168.1.10", "ttl_s": 300},
                                       dry_run=True))
    assert result.ok is True
    assert switch.armed() == {}


def test_the_dead_man_switch_survives_a_restart(tmp_path):
    """Agent chết rồi sống lại vẫn phải biết nó đang nợ một lần gỡ cách ly.

    Không đọc lại trạng thái thì `expired()` luôn rỗng sau khởi động lại,
    không ai gỡ luật nữa, và máy nằm ngoài mạng vĩnh viễn — đúng thảm hoạ mà
    dead-man sinh ra để chặn. 12 test cũ đều xanh vì không test nào mô phỏng
    việc tiến trình chết đi.
    """
    from shield.security.response import DeadManSwitch

    state = tmp_path / "deadman.json"
    first = DeadManSwitch(state)
    first.arm("10.0.0.99", 1.0)

    # Tiến trình mới, cùng file trạng thái.
    second = DeadManSwitch(state)
    assert "10.0.0.99" in second.armed(), "khởi động lại là quên mất đang cách ly ai"

    time.sleep(1.2)
    assert second.expired() == ["10.0.0.99"]


def test_deadlines_are_wall_clock_not_monotonic(tmp_path):
    """Hạn chót ghi ra đĩa phải so được ở tiến trình khác.

    `time.monotonic()` chỉ có nghĩa trong đúng một tiến trình; ghi nó ra rồi
    đọc lại chỗ khác là so hai thang đo khác nhau.
    """
    import json

    from shield.security.response import DeadManSwitch

    state = tmp_path / "deadman.json"
    DeadManSwitch(state).arm("10.0.0.99", 60.0)
    written = json.loads(state.read_text(encoding="utf-8"))["10.0.0.99"]
    assert abs(written - (time.time() + 60.0)) < 5.0


def test_a_tampered_deadline_cannot_pin_isolation_forever(tmp_path):
    """File trạng thái hỏng với hạn chót năm 2099 sẽ ghim cách ly vĩnh viễn."""
    import json

    from shield.security.response import MAX_DEADMAN_TTL_S, DeadManSwitch

    state = tmp_path / "deadman.json"
    state.write_text(json.dumps({"10.0.0.99": time.time() + 10 ** 9}), encoding="utf-8")
    switch = DeadManSwitch(state)
    assert switch.armed()["10.0.0.99"] <= time.time() + MAX_DEADMAN_TTL_S + 1


def test_a_corrupt_state_file_never_raises(tmp_path):
    """Không đọc được trạng thái thì bắt đầu lại từ rỗng, không được ném lỗi."""
    from shield.security.response import DeadManSwitch

    state = tmp_path / "deadman.json"
    state.write_text("{ this is not json", encoding="utf-8")
    assert DeadManSwitch(state).armed() == {}
