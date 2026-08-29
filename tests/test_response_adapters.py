"""Bốn adapter phản ứng: snapshot, chặn IP, giới hạn tốc độ, cách ly (mục 4.2, 4.3).

Hợp đồng adapter chỉ có giá trị nếu KHÔNG có ngoại lệ. Một adapter được miễn
`verify()` vì "nó an toàn mà" là adapter đầu tiên trong một danh sách sẽ dài ra.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest

from shield.decision.models import ACTION_SPECS
from shield.response.adapters.base import ApplyResult
from shield.response.adapters.isolate_endpoint import IsolateEndpointAdapter
from shield.response.adapters.rate_limit import RateLimitAdapter
from shield.response.adapters.snapshot import SnapshotAdapter
from shield.response.adapters.temporary_block import TemporaryBlockAdapter
from shield.security.isolation import build_ruleset
from shield.security.response import DeadManSwitch

ROOT = Path(__file__).resolve().parent.parent
ADAPTERS = (SnapshotAdapter, TemporaryBlockAdapter, RateLimitAdapter, IsolateEndpointAdapter)


def run(coro):
    return asyncio.run(coro)


class FakeHelper:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    async def call(self, action, params):
        self.calls.append((action, dict(params)))
        return self.responses.get(action, {"ok": True, "message": ""})


# --- hợp đồng không có ngoại lệ ---


@pytest.mark.parametrize("cls", ADAPTERS, ids=[c.__name__ for c in ADAPTERS])
def test_every_adapter_implements_the_whole_contract(cls):
    for method in ("preview", "check_preconditions", "apply", "verify", "rollback"):
        assert callable(getattr(cls, method, None)), f"{cls.__name__} thiếu {method}"
    assert isinstance(cls.reversible, bool)
    assert isinstance(cls.human_only, bool)
    assert cls.action in ACTION_SPECS, f"{cls.action} không có trong ACTION_SPECS"


@pytest.mark.parametrize("cls", ADAPTERS, ids=[c.__name__ for c in ADAPTERS])
def test_the_adapter_agrees_with_the_action_spec(cls):
    spec = ACTION_SPECS[cls.action]
    assert cls.reversible == spec["reversible"], cls.action
    from shield.decision.models import MAX_AUTOMATIC_LEVEL

    if spec["level"] > MAX_AUTOMATIC_LEVEL:
        assert cls.human_only is True, f"{cls.action} ở Level {spec['level']} mà không human_only"


def test_every_action_in_the_spec_has_an_adapter_or_is_deliberately_absent():
    """`alert` không cần adapter (nó không đổi trạng thái gì); `stop_process` cố
    ý chưa có, vì nó không đảo ngược được và 2.0 không tự động hoá nó."""
    covered = {cls.action for cls in ADAPTERS}
    deliberate = {"alert", "stop_process"}
    assert covered | deliberate == set(ACTION_SPECS)


def test_the_agent_registers_every_implemented_adapter():
    source = (ROOT / "shield/agent/__main__.py").read_text(encoding="utf-8")
    index = source.index("adapters = {")
    block = source[index:index + 900]
    for cls in ADAPTERS:
        assert f'"{cls.action}"' in block, f"{cls.action} chưa được đăng ký"


# --- snapshot ---


def test_a_snapshot_verifies_the_file_actually_exists(tmp_path):
    """"Lệnh chạy xong" không chứng minh file đã được ghi: đĩa đầy giữa chừng,
    thư mục bị xoá dưới chân, hay một lỗi ghi im lặng đều cho cùng exit code."""
    target = tmp_path / "snap.txt"

    async def fake():
        target.write_text("nội dung")
        return True, str(target)

    adapter = SnapshotAdapter(snapshot_fn=fake, snapshot_dir=tmp_path)
    assert run(adapter.check_preconditions({})).ok is True
    applied = run(adapter.apply({}, "k"))
    verified = run(adapter.verify({}, applied))
    assert verified.verified is True
    assert verified.observed["size"] > 0


def test_a_snapshot_that_wrote_nothing_fails_verification(tmp_path):
    target = tmp_path / "empty.txt"

    async def fake():
        target.write_text("")
        return True, str(target)

    adapter = SnapshotAdapter(snapshot_fn=fake, snapshot_dir=tmp_path)
    applied = run(adapter.apply({}, "k"))
    result = run(adapter.verify({}, applied))
    assert result.verified is False and result.reason_key == "response.snapshot_err_empty"


def test_a_missing_snapshot_file_fails_verification(tmp_path):
    async def fake():
        return True, str(tmp_path / "khong-ton-tai.txt")

    adapter = SnapshotAdapter(snapshot_fn=fake, snapshot_dir=tmp_path)
    applied = run(adapter.apply({}, "k"))
    assert run(adapter.verify({}, applied)).verified is False


def test_rolling_back_a_snapshot_deletes_the_file(tmp_path):
    target = tmp_path / "snap.txt"

    async def fake():
        target.write_text("x")
        return True, str(target)

    adapter = SnapshotAdapter(snapshot_fn=fake, snapshot_dir=tmp_path)
    applied = run(adapter.apply({}, "k"))
    assert run(adapter.rollback({}, applied)).ok is True
    assert not target.exists()
    # Idempotent: xoá một file không tồn tại là thành công.
    assert run(adapter.rollback({}, applied)).ok is True


# --- giới hạn tốc độ ---


def _rate(helper, ips=(), **kwargs):
    async def reader():
        return json.dumps({"nftables": [
            {"set": {"table": "shield", "name": "ratelimited_ips",
                     "elem": [{"elem": {"val": ip}} for ip in ips]}}]})
    return RateLimitAdapter(helper, nft_reader=reader, **kwargs)


def test_rate_limiting_uses_its_own_nft_set():
    """Dùng chung set với `block_ip` nghĩa là gỡ giới hạn tốc độ sẽ gỡ nhầm
    một lệnh chặn đang có hiệu lực."""
    helper = FakeHelper()
    applied = run(_rate(helper).apply({"ip": "203.0.113.9"}, "k"))
    assert applied.ok and helper.calls[0][0] == "rate_limit_ip"
    verified = run(_rate(helper, ips=("203.0.113.9",)).verify({"ip": "203.0.113.9"}, applied))
    assert verified.verified is True
    # Có mặt trong blocked_ips KHÔNG được tính là đã giới hạn tốc độ.
    async def wrong_set():
        return json.dumps({"nftables": [
            {"set": {"table": "shield", "name": "blocked_ips",
                     "elem": [{"elem": {"val": "203.0.113.9"}}]}}]})
    other = RateLimitAdapter(helper, nft_reader=wrong_set)
    assert run(other.verify({"ip": "203.0.113.9"}, applied)).verified is False


def test_rate_limiting_protects_the_same_addresses_as_blocking():
    """Làm chậm gateway không phá mạng như chặn hẳn, nhưng nó biến mọi thứ
    thành 'lúc được lúc không' — khó chẩn đoán hơn cả đứt hẳn."""
    adapter = _rate(FakeHelper(), gateway="192.168.1.1", resolvers=("8.8.8.8",),
                    management="192.168.1.20")
    for target in ("192.168.1.1", "8.8.8.8", "192.168.1.20", "127.0.0.1"):
        check = run(adapter.check_preconditions({"ip": target, "ttl_s": 300}))
        assert check.ok is False, target
        assert check.reason_key


def test_rate_limiting_must_have_a_deadline():
    check = run(_rate(FakeHelper()).check_preconditions({"ip": "203.0.113.9", "ttl_s": 0}))
    assert check.ok is False and check.reason_key == "response.block_err_no_ttl"


def test_rolling_back_a_rate_limit_is_idempotent():
    helper = FakeHelper({"unrate_limit_ip": {"ok": False,
                                             "message": "No such file or directory"}})
    assert run(_rate(helper).rollback({"ip": "1.2.3.4"}, ApplyResult(True))).ok is True


# --- cách ly ---


def _isolate(helper, ruleset="", dead_man=None, tmp_path=None):
    async def reader():
        return ruleset
    return IsolateEndpointAdapter(
        helper, dead_man=dead_man or DeadManSwitch(tmp_path / "dm.json"),
        nft_reader=reader)


def _real_ruleset(mgmt="192.168.1.20"):
    """JSON giống nftables thật trả về cho table cách ly."""
    return json.dumps({"nftables": [
        {"table": {"family": "inet", "name": "shield_isolation"}},
        *[{"chain": {"family": "inet", "table": "shield_isolation", "name": name,
                     "type": "filter", "hook": name, "policy": "drop"}}
          for name in ("input", "output")],
        *[{"rule": {"table": "shield_isolation", "chain": name, "expr": [
            {"match": {"left": {"meta": {"key": "iif"}}, "op": "==", "right": "lo"}},
            {"verdict": {"accept": None}}]}}
          for name in ("input", "output")],
        *[{"rule": {"table": "shield_isolation", "chain": name, "expr": [
            {"match": {"left": {"payload": {"protocol": "ip",
                                            "field": "saddr" if name == "input" else "daddr"}},
                       "op": "==", "right": mgmt}},
            {"verdict": {"accept": None}}]}}
          for name in ("input", "output")],
    ]})


def test_isolation_is_never_automatic():
    """Một máy tự cách ly mình vì một detector chưa hiệu chuẩn là một sự cố tự
    gây ra."""
    from shield.decision.models import MAX_AUTOMATIC_LEVEL

    assert IsolateEndpointAdapter.human_only is True
    assert ACTION_SPECS["isolate_endpoint"]["level"] > MAX_AUTOMATIC_LEVEL


def test_isolation_is_refused_without_a_dead_man_switch(tmp_path):
    adapter = IsolateEndpointAdapter(FakeHelper(), dead_man=None, nft_reader=None)
    check = run(adapter.check_preconditions({"management_ip": "192.168.1.20", "ttl_s": 300}))
    assert check.ok is False and check.reason_key == "response.isolate_err_no_deadman"


def test_isolation_is_refused_without_a_way_to_verify(tmp_path):
    """Không kiểm chứng được thì không được áp — đó chính là lời nói dối cũ."""
    adapter = IsolateEndpointAdapter(FakeHelper(),
                                     dead_man=DeadManSwitch(tmp_path / "dm.json"),
                                     nft_reader=None)
    check = run(adapter.check_preconditions({"management_ip": "192.168.1.20", "ttl_s": 300}))
    assert check.ok is False and check.reason_key == "response.isolate_err_no_reader"


def test_the_dead_man_switch_is_armed_only_after_verification(tmp_path):
    """Arm cho một lần cách ly chưa từng xảy ra nghĩa là trạng thái trên đĩa
    nói dối về việc máy đang ở đâu."""
    switch = DeadManSwitch(tmp_path / "dm.json")
    helper = FakeHelper()
    adapter = _isolate(helper, ruleset="", dead_man=switch, tmp_path=tmp_path)
    plan = {"management_ip": "192.168.1.20", "ttl_s": 300}
    applied = run(adapter.apply(plan, "k"))
    assert applied.ok is True
    assert switch.armed() == {}, "arm trước khi kiểm chứng"
    result = run(adapter.verify(plan, applied))
    assert result.verified is False
    assert switch.armed() == {}, "arm dù kiểm chứng thất bại"


def test_a_verified_isolation_arms_the_switch(tmp_path):
    switch = DeadManSwitch(tmp_path / "dm.json")
    adapter = _isolate(FakeHelper(), ruleset=_real_ruleset(), dead_man=switch,
                       tmp_path=tmp_path)
    plan = {"management_ip": "192.168.1.20", "ttl_s": 300}
    applied = run(adapter.apply(plan, "k"))
    result = run(adapter.verify(plan, applied))
    assert result.verified is True
    assert "192.168.1.20" in switch.armed()
    assert result.observed["dead_man_deadline"] > 0


def test_a_failed_release_keeps_the_deadline_armed(tmp_path):
    """Disarm khi gỡ hỏng nghĩa là không ai thử nữa và máy nằm ngoài mạng
    vĩnh viễn."""
    switch = DeadManSwitch(tmp_path / "dm.json")
    switch.arm("192.168.1.20", 300)
    helper = FakeHelper({"release_isolation": {"ok": False, "message": "nft bận"}})
    adapter = _isolate(helper, dead_man=switch, tmp_path=tmp_path)
    result = run(adapter.rollback({"management_ip": "192.168.1.20"},
                                  ApplyResult(True, "", {"management_ip": "192.168.1.20"})))
    assert result.ok is False
    assert "192.168.1.20" in switch.armed()


def test_the_verification_uses_the_same_checker_as_the_helper(tmp_path):
    """Hai lần kiểm không thừa: helper kiểm ngay sau khi áp, adapter kiểm ở
    thời điểm job chuyển sang VERIFYING — giữa hai mốc có thể có người xoá
    table hoặc một lượt `nft flush ruleset` từ script khác."""
    source = (ROOT / "shield/response/adapters/isolate_endpoint.py").read_text(encoding="utf-8")
    assert "from shield.security.isolation import verify_isolation" in source
    assert build_ruleset("192.168.1.20")   # cùng module, cùng nguồn sự thật


# --- nâng cấp một bản cài cũ ---


def test_the_rate_limit_set_is_added_to_an_existing_table():
    """Máy đã chạy 1.x có `table inet shield` rồi, nên `set ratelimited_ips` sẽ
    không bao giờ được tạo nếu `ensure_shield_table` trả về sớm — và tính năng
    mới im lặng không hoạt động trên đúng những máy đã dùng lâu nhất."""
    source = (ROOT / "shield/agent/actions.py").read_text(encoding="utf-8")
    index = source.index("async def ensure_shield_table")
    block = source[index:index + 1400]
    assert "_ensure_rate_limit()" in block
    assert 'return True, "đã tồn tại"' not in block.split("if check.returncode == 0:")[1][:200]


def test_the_rate_limit_rule_is_not_appended_twice():
    """`nft add rule` nối thêm một luật trùng mỗi lần gọi; sau vài lần khởi
    động lại chain sẽ đầy những luật giống hệt nhau."""
    source = (ROOT / "shield/agent/actions.py").read_text(encoding="utf-8")
    index = source.index("async def _ensure_rate_limit")
    block = source[index:index + 1200]
    assert "list" in block and "@ratelimited_ips" in block
    assert block.index("@ratelimited_ips") < block.index('"add", "rule"')


def test_no_adapter_imports_the_ai_package():
    for path in sorted((ROOT / "shield/response/adapters").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = ""
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
            elif isinstance(node, ast.Import):
                module = node.names[0].name
            assert not module.startswith("shield.ai"), f"{path.name} -> {module}"
