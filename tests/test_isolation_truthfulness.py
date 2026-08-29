"""isolate_endpoint phải nói thật (KE-HOACH-SHIELD-2.0.md Batch 2.0-P0).

Tiêu chí hoàn tất batch, chép nguyên văn:

> Không một response nào được phép trả `ok=True` nếu postcondition chưa được
> kiểm chứng từ trạng thái hệ thống thật.

Trước batch này, `isolate_endpoint` arm dead-man switch rồi trả về
"đã cách ly" — không một luật firewall nào được áp. Người vận hành nhìn thấy
chữ "đã cách ly" trong khi máy vẫn nối mạng bình thường. Đó là dạng hỏng tệ
nhất trong một sản phẩm phòng thủ: nó khiến người ta ngừng tìm cách khác.
"""

from __future__ import annotations

import asyncio


from shield.security.response import Quarantine, ResponseExecutor, DeadManSwitch


class RecordingClient:
    """Privileged helper giả: ghi lại lời gọi và trả về kết quả đặt sẵn."""

    def __init__(self, responses: dict | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.responses = responses or {}

    async def call(self, action: str, params: dict) -> dict:
        self.calls.append((action, dict(params)))
        return self.responses.get(action, {"ok": True, "action": action, "message": ""})


def run(coro):
    return asyncio.run(coro)


# --- lời nói dối gốc ---


def test_isolation_without_a_privileged_helper_is_refused(tmp_path):
    """Không có helper thì không áp được luật nào — phải nói thẳng là không làm được.

    Đây chính là bug: bản cũ vẫn trả ok=True ở đúng tình huống này.
    """
    executor = ResponseExecutor(
        Quarantine(tmp_path / "q"),
        dead_man=DeadManSwitch(tmp_path / "deadman.json"),
        privileged_client=None,
    )
    result = run(executor._dispatch(
        "isolate_endpoint", {"management_ip": "192.168.1.10", "ttl_s": 300}, dry_run=False))
    assert result.ok is False
    assert "helper" in result.message.lower()


def test_isolation_actually_calls_the_privileged_helper(tmp_path):
    client = RecordingClient()
    executor = ResponseExecutor(
        Quarantine(tmp_path / "q"),
        dead_man=DeadManSwitch(tmp_path / "deadman.json"),
        privileged_client=client,
    )
    result = run(executor._dispatch(
        "isolate_endpoint", {"management_ip": "192.168.1.10", "ttl_s": 300}, dry_run=False))
    assert result.ok is True
    assert [action for action, _ in client.calls] == ["isolate_endpoint"]
    assert client.calls[0][1]["management_ip"] == "192.168.1.10"


def test_a_failed_apply_never_arms_the_dead_man_switch(tmp_path):
    """Dead-man chỉ được arm SAU khi firewall đã áp thật (mục 0.2).

    Arm trước rồi apply hỏng nghĩa là: hệ thống tin rằng nó đang cách ly,
    ghi ra đĩa một hạn chót, rồi mỗi lần khởi động lại đều cố gỡ một thứ
    chưa từng tồn tại.
    """
    client = RecordingClient({"isolate_endpoint": {"ok": False, "message": "nft: no such table"}})
    switch = DeadManSwitch(tmp_path / "deadman.json")
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=switch, privileged_client=client)
    result = run(executor._dispatch(
        "isolate_endpoint", {"management_ip": "192.168.1.10", "ttl_s": 300}, dry_run=False))
    assert result.ok is False
    assert switch.armed() == {}, "arm dead-man cho một lần cách ly chưa từng xảy ra"


def test_a_dry_run_touches_neither_helper_nor_switch(tmp_path):
    client = RecordingClient()
    switch = DeadManSwitch(tmp_path / "deadman.json")
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=switch, privileged_client=client)
    result = run(executor._dispatch(
        "isolate_endpoint", {"management_ip": "192.168.1.10", "ttl_s": 300}, dry_run=True))
    assert result.ok is True
    assert client.calls == []
    assert switch.armed() == {}


# --- gỡ cách ly ---


def test_releasing_isolation_calls_the_helper_and_disarms(tmp_path):
    client = RecordingClient()
    switch = DeadManSwitch(tmp_path / "deadman.json")
    switch.arm("192.168.1.10", 300)
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=switch, privileged_client=client)
    result = run(executor._dispatch(
        "release_isolation", {"management_ip": "192.168.1.10"}, dry_run=False))
    assert result.ok is True
    assert [action for action, _ in client.calls] == ["release_isolation"]
    assert switch.armed() == {}


def test_a_failed_release_keeps_the_deadline_armed(tmp_path):
    """Gỡ hỏng mà vẫn disarm nghĩa là không ai thử gỡ lần nữa — máy nằm ngoài
    mạng vĩnh viễn, đúng thảm hoạ dead-man sinh ra để chặn."""
    client = RecordingClient({"release_isolation": {"ok": False, "message": "nft busy"}})
    switch = DeadManSwitch(tmp_path / "deadman.json")
    switch.arm("192.168.1.10", 300)
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=switch, privileged_client=client)
    result = run(executor._dispatch(
        "release_isolation", {"management_ip": "192.168.1.10"}, dry_run=False))
    assert result.ok is False
    assert "192.168.1.10" in switch.armed()


def test_releasing_twice_is_idempotent(tmp_path):
    """Rollback phải idempotent (mục 0.2)."""
    client = RecordingClient()
    switch = DeadManSwitch(tmp_path / "deadman.json")
    switch.arm("192.168.1.10", 300)
    executor = ResponseExecutor(Quarantine(tmp_path / "q"), dead_man=switch, privileged_client=client)
    first = run(executor._dispatch("release_isolation", {"management_ip": "192.168.1.10"}, dry_run=False))
    second = run(executor._dispatch("release_isolation", {"management_ip": "192.168.1.10"}, dry_run=False))
    assert first.ok is True and second.ok is True
