"""Cách ly endpoint chặn traffic THẬT — chạy trong network namespace.

KE-HOACH-SHIELD-2.0.md mục 0.2, "Test bắt buộc":

    - Test trong network namespace chứng minh traffic bị chặn thật.
    - Management path vẫn hoạt động.
    - Hết TTL thì traffic được khôi phục.
    - Apply lỗi giữa chừng không để lại rule rác.

Vì sao phải có file này dù đã có 23 test không cần root: những test kia chứng
minh Shield DỰNG ĐÚNG chuỗi ruleset và ĐỌC ĐÚNG JSON. Không test nào trong số
đó chứng minh nftables hiểu chuỗi ấy giống như chúng ta nghĩ. Khoảng cách đó
đúng bằng khoảng cách giữa "báo đã cách ly" và "đã cách ly".

Chạy:

    sudo SHIELD_NETNS_TESTS=1 .venv/bin/python -m pytest tests/test_isolation_netns.py -v

Mặc định bỏ qua: cần CAP_NET_ADMIN và tạo/xoá netns thật trên máy đang chạy.
"""

from __future__ import annotations

import asyncio
import os
import subprocess

import pytest

from shield.security.isolation import build_ruleset, delete_ruleset, verify_isolation

pytestmark = [
    pytest.mark.netns,
    pytest.mark.skipif(os.geteuid() != 0, reason="cần root để tạo network namespace"),
    pytest.mark.skipif(os.environ.get("SHIELD_NETNS_TESTS") != "1",
                       reason="đặt SHIELD_NETNS_TESTS=1 để chạy có chủ đích"),
]

NS = "shield-iso-test"
MGMT_IP = "10.77.0.1"      # phía host: đóng vai máy quản trị
OTHER_IP = "10.77.0.3"     # phía host: đóng vai mọi thứ KHÔNG phải quản trị
NS_IP = "10.77.0.2"        # phía namespace: máy bị cách ly


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check)


def in_ns(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run("ip", "netns", "exec", NS, *args, check=check)


def ping_ns_from(source: str) -> bool:
    """Từ host, ping máy trong namespace bằng một địa chỉ nguồn cụ thể."""
    result = run("ping", "-c", "2", "-W", "2", "-I", source, NS_IP, check=False)
    return result.returncode == 0


@pytest.fixture()
def namespace():
    run("ip", "netns", "del", NS, check=False)
    run("ip", "link", "del", "shield-veth-h", check=False)
    run("ip", "netns", "add", NS)
    try:
        run("ip", "link", "add", "shield-veth-h", "type", "veth", "peer", "name", "shield-veth-n")
        run("ip", "link", "set", "shield-veth-n", "netns", NS)
        run("ip", "addr", "add", f"{MGMT_IP}/24", "dev", "shield-veth-h")
        run("ip", "addr", "add", f"{OTHER_IP}/24", "dev", "shield-veth-h")
        run("ip", "link", "set", "shield-veth-h", "up")
        in_ns("ip", "addr", "add", f"{NS_IP}/24", "dev", "shield-veth-n")
        in_ns("ip", "link", "set", "shield-veth-n", "up")
        in_ns("ip", "link", "set", "lo", "up")
        yield
    finally:
        run("ip", "netns", "del", NS, check=False)
        run("ip", "link", "del", "shield-veth-h", check=False)


def apply_isolation_in_ns(management_ip: str = MGMT_IP, *, preserve_dns: bool = False) -> None:
    ruleset = build_ruleset(management_ip, preserve_dns=preserve_dns)
    proc = subprocess.run(["ip", "netns", "exec", NS, "nft", "-f", "-"],
                          input=ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, f"nft từ chối ruleset Shield dựng ra: {proc.stderr}"


def release_isolation_in_ns() -> None:
    in_ns("nft", *delete_ruleset().split(), check=False)


def isolation_json() -> str:
    result = in_ns("nft", "-j", "list", "table", "inet", "shield_isolation", check=False)
    return result.stdout if result.returncode == 0 else ""


# --- cái quan trọng nhất: luật Shield dựng ra có được kernel chấp nhận không ---


def test_the_generated_ruleset_is_accepted_by_a_real_kernel(namespace):
    """Không test nào chạy trên máy thường bắt được lỗi cú pháp nftables."""
    apply_isolation_in_ns()
    assert isolation_json(), "table không tồn tại sau khi nft báo thành công"


def test_verification_agrees_with_the_real_kernel(namespace):
    """verify_isolation() đọc JSON THẬT của nftables, không phải JSON tự chế.

    Đây là mắt xích dễ gãy âm thầm nhất: nftables đổi định dạng JSON giữa các
    phiên bản, verify tưởng hỏng và tự gỡ cách ly ngay sau khi áp.
    """
    apply_isolation_in_ns()
    ok, reason = verify_isolation(isolation_json(), MGMT_IP)
    assert ok is True, f"kernel đang giữ đúng luật nhưng verify nói không: {reason}"


def test_verification_with_dns_preserved_agrees_with_the_real_kernel(namespace):
    apply_isolation_in_ns(preserve_dns=True)
    ok, reason = verify_isolation(isolation_json(), MGMT_IP, preserve_dns=True)
    assert ok is True, reason


# --- traffic thật ---


def test_traffic_flows_before_isolation(namespace):
    """Nếu test này hỏng thì mọi kết luận bên dưới đều vô nghĩa."""
    assert ping_ns_from(MGMT_IP) is True
    assert ping_ns_from(OTHER_IP) is True


def test_isolation_actually_blocks_non_management_traffic(namespace):
    """Bằng chứng cuối cùng: gói tin thật không đi qua nữa."""
    assert ping_ns_from(OTHER_IP) is True
    apply_isolation_in_ns()
    assert ping_ns_from(OTHER_IP) is False, "báo đã cách ly nhưng traffic vẫn đi qua"


def test_the_management_path_keeps_working(namespace):
    """Cách ly mà cắt luôn đường quản trị nghĩa là không ai sửa được máy nữa."""
    apply_isolation_in_ns()
    assert ping_ns_from(MGMT_IP) is True, "cách ly cắt mất chính đường vào để gỡ nó"


def test_loopback_keeps_working_inside_the_isolated_host(namespace):
    """Guardian, IPC agent-UI và socket helper đều đi qua loopback."""
    apply_isolation_in_ns()
    result = in_ns("ping", "-c", "2", "-W", "2", "127.0.0.1", check=False)
    assert result.returncode == 0, "cách ly cắt loopback: guardian và UI sẽ chết theo"


def test_releasing_restores_traffic(namespace):
    """Hết TTL thì traffic được khôi phục."""
    apply_isolation_in_ns()
    assert ping_ns_from(OTHER_IP) is False
    release_isolation_in_ns()
    assert ping_ns_from(OTHER_IP) is True, "đã gỡ nhưng mạng không quay lại"


def test_releasing_is_idempotent_against_a_real_kernel(namespace):
    apply_isolation_in_ns()
    release_isolation_in_ns()
    release_isolation_in_ns()
    assert isolation_json() == ""
    assert ping_ns_from(OTHER_IP) is True


def test_reapplying_does_not_stack_rules(namespace):
    """Áp hai lần phải cho đúng một trạng thái, không nhân đôi luật."""
    apply_isolation_in_ns()
    first = isolation_json()
    release_isolation_in_ns()
    apply_isolation_in_ns()
    assert isolation_json().count('"accept"') == first.count('"accept"')


# --- không để lại rule rác ---


def test_a_rejected_ruleset_leaves_nothing_behind(namespace):
    """Apply lỗi giữa chừng không để lại rule rác.

    Giao dịch nft là nguyên tử, nhưng đó là một lời hứa của công cụ khác —
    kiểm chứng nó chứ đừng tin.
    """
    broken = build_ruleset(MGMT_IP).replace("iif lo accept", "iif lo accept\n        khong-phai-lenh-nft")
    proc = subprocess.run(["ip", "netns", "exec", NS, "nft", "-f", "-"],
                          input=broken, capture_output=True, text=True)
    assert proc.returncode != 0
    assert isolation_json() == "", "ruleset hỏng vẫn để lại table nửa vời"
    assert ping_ns_from(OTHER_IP) is True, "áp hỏng nhưng mạng đã đứt"


def test_isolation_never_touches_the_block_ip_table(namespace):
    """Gỡ cách ly không được xoá nhầm luật chặn IP đang có hiệu lực."""
    from shield.agent.actions import _NFT_RULESET

    proc = subprocess.run(["ip", "netns", "exec", NS, "nft", "-f", "-"],
                          input=_NFT_RULESET, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    apply_isolation_in_ns()
    release_isolation_in_ns()
    still_there = in_ns("nft", "list", "table", "inet", "shield", check=False)
    assert still_there.returncode == 0, "gỡ cách ly đã xoá mất table chặn IP"


# --- đường đi thật qua actions (không phải chuỗi ruleset trần) ---


def test_apply_and_verify_through_the_real_action_path(namespace, monkeypatch):
    """Đi qua đúng actions.apply_isolation, chỉ đổi chỗ chạy nft sang netns."""
    from shield.agent import actions

    original = asyncio.create_subprocess_exec

    async def in_namespace(program, *args, **kwargs):
        if program == "nft":
            return await original("ip", "netns", "exec", NS, "nft", *args, **kwargs)
        return await original(program, *args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", in_namespace)
    ok, message = asyncio.run(actions.apply_isolation(MGMT_IP))
    assert ok is True, message
    assert ping_ns_from(OTHER_IP) is False
    assert ping_ns_from(MGMT_IP) is True

    ok, message = asyncio.run(actions.release_isolation())
    assert ok is True, message
    assert ping_ns_from(OTHER_IP) is True

    # Idempotent trên kernel thật, không chỉ trên mock.
    ok, _ = asyncio.run(actions.release_isolation())
    assert ok is True


# --- table chặn/giới hạn tốc độ (không phải table cách ly) ---


def test_the_shield_table_is_accepted_by_a_real_kernel(namespace):
    """Ruleset của `table inet shield` cũng phải được kernel chấp nhận.

    Không test nào chạy trên máy thường bắt được lỗi cú pháp nftables. Luật
    `limit rate over ...` là thứ mới ở 2.0 và chưa từng được kernel nào đọc.
    """
    from shield.agent.actions import _NFT_RULESET

    proc = subprocess.run(["ip", "netns", "exec", NS, "nft", "-f", "-"],
                          input=_NFT_RULESET, capture_output=True, text=True)
    assert proc.returncode == 0, f"nft từ chối ruleset: {proc.stderr}"
    listing = in_ns("nft", "list", "table", "inet", "shield").stdout
    assert "ratelimited_ips" in listing
    assert "limit rate over" in listing


def test_the_rate_limit_rule_is_added_to_an_existing_old_table(namespace):
    """Máy đã chạy 1.x có table này rồi. Nếu `ensure_shield_table` trả về sớm
    thì set và luật mới không bao giờ được tạo, và tính năng im lặng không hoạt
    động trên đúng những máy đã dùng lâu nhất.
    """
    from shield.agent import actions

    old_ruleset = """
table inet shield {
    set blocked_ips { type ipv4_addr; flags timeout; }
    set blocked_macs { type ether_addr; flags timeout; }
    chain input {
        type filter hook input priority filter; policy accept;
        ip saddr @blocked_ips drop
        ether saddr @blocked_macs drop
    }
    chain output {
        type filter hook output priority filter; policy accept;
        ip daddr @blocked_ips drop
    }
}
"""
    proc = subprocess.run(["ip", "netns", "exec", NS, "nft", "-f", "-"],
                          input=old_ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "ratelimited_ips" not in in_ns("nft", "list", "table", "inet", "shield").stdout

    original = asyncio.create_subprocess_exec

    async def in_namespace(program, *args, **kwargs):
        if program == "nft":
            return await original("ip", "netns", "exec", NS, "nft", *args, **kwargs)
        return await original(program, *args, **kwargs)

    import unittest.mock

    with unittest.mock.patch.object(asyncio, "create_subprocess_exec", in_namespace):
        ok, message = asyncio.run(actions.ensure_shield_table())
        assert ok, message
        listing = in_ns("nft", "list", "table", "inet", "shield").stdout
        assert "ratelimited_ips" in listing, "set mới không được thêm vào table cũ"
        assert "limit rate over" in listing, "luật rate-limit không được thêm"

        # Gọi lại KHÔNG được nối thêm một luật trùng.
        asyncio.run(actions.ensure_shield_table())
        asyncio.run(actions.ensure_shield_table())
        listing = in_ns("nft", "list", "chain", "inet", "shield", "input").stdout
        assert listing.count("@ratelimited_ips") == 1, \
            f"luật rate-limit bị nối thêm nhiều lần:\n{listing}"


def test_rate_limiting_an_address_is_verifiable(namespace):
    """Đọc lại set từ kernel và tìm địa chỉ — đúng thứ adapter làm."""
    from shield.agent import actions
    from shield.response.adapters.rate_limit import _element_present

    original = asyncio.create_subprocess_exec

    async def in_namespace(program, *args, **kwargs):
        if program == "nft":
            return await original("ip", "netns", "exec", NS, "nft", *args, **kwargs)
        return await original(program, *args, **kwargs)

    import unittest.mock

    with unittest.mock.patch.object(asyncio, "create_subprocess_exec", in_namespace):
        ok, message = asyncio.run(actions.rate_limit_ip("203.0.113.9"))
        assert ok, message
        raw = in_ns("nft", "-j", "list", "table", "inet", "shield").stdout
        present, elements = _element_present(raw, "203.0.113.9")
        assert present, f"không thấy địa chỉ trong set: {elements}"

        ok, message = asyncio.run(actions.unrate_limit_ip("203.0.113.9"))
        assert ok, message
        raw = in_ns("nft", "-j", "list", "table", "inet", "shield").stdout
        assert _element_present(raw, "203.0.113.9")[0] is False
