"""Ruleset cách ly và việc kiểm chứng hậu điều kiện (KE-HOACH-SHIELD-2.0.md 0.2).

Toàn bộ file này chạy không cần root: `build_ruleset` và `verify_isolation` là
hàm thuần. Đây là chỗ đặt phần lớn niềm tin — test trong netns cần quyền đặc
biệt nên hiếm khi chạy, còn các test dưới đây chạy mỗi lần commit.
"""

from __future__ import annotations

import json

import pytest

from shield.security.isolation import (
    ISOLATION_TABLE,
    build_ruleset,
    delete_ruleset,
    isolation_present,
    verify_isolation,
)


# --- dựng ruleset ---


def test_the_ruleset_lives_in_its_own_table():
    """Dùng lại table của block_ip nghĩa là gỡ cách ly có thể xoá nhầm luật
    chặn IP đang có hiệu lực."""
    text = build_ruleset("192.168.1.10")
    assert f"table inet {ISOLATION_TABLE}" in text
    assert "table inet shield " not in text
    assert delete_ruleset() == f"delete table inet {ISOLATION_TABLE}"


def test_both_hooks_default_to_drop():
    text = build_ruleset("192.168.1.10")
    assert text.count("policy drop;") == 2
    assert "hook input" in text and "hook output" in text


def test_loopback_is_always_preserved():
    """Mất loopback là mất guardian, mất IPC agent-UI và mất luôn đường gỡ."""
    text = build_ruleset("192.168.1.10")
    assert "iif lo accept" in text
    assert "oif lo accept" in text


def test_the_management_address_is_an_exception_not_a_target():
    """Mục 0.2: 'Management IP là peer được phép giữ kết nối, không phải target
    bị block.' Bản cũ gọi unblock_ip lên chính địa chỉ này."""
    text = build_ruleset("192.168.1.10")
    assert "ip saddr 192.168.1.10 accept" in text
    assert "ip daddr 192.168.1.10 accept" in text
    assert "drop" not in text.split("192.168.1.10")[0].split("\n")[-1]


def test_established_connections_are_not_blanket_accepted():
    """Cho ct established đi tiếp nghĩa là phiên C2 của kẻ tấn công sống sót."""
    assert "established" not in build_ruleset("192.168.1.10")


def test_dns_is_only_preserved_when_asked():
    assert "53" not in build_ruleset("192.168.1.10")
    with_dns = build_ruleset("192.168.1.10", preserve_dns=True)
    assert "udp sport 53 accept" in with_dns
    assert "udp dport 53 accept" in with_dns


@pytest.mark.parametrize("bad", ["0.0.0.0", "224.0.0.1", "127.0.0.1", "::1", "not-an-ip", ""])
def test_unsafe_management_addresses_are_refused(bad):
    with pytest.raises(ValueError):
        build_ruleset(bad)


def test_the_address_is_never_interpolated_unvalidated():
    """Không có đường nào để chuỗi tuỳ ý lọt vào ruleset."""
    with pytest.raises(ValueError):
        build_ruleset("192.168.1.10 accept; ip saddr 0.0.0.0/0 accept #")


# --- kiểm chứng hậu điều kiện ---


def _nft_json(*, policy="drop", table=ISOLATION_TABLE, mgmt="192.168.1.10",
              loopback=True, dns=False, chains=("input", "output"), dns_port=53):
    """JSON giống thứ nftables THẬT trả về.

    `dns_port` mặc định là số nguyên vì đó là cái nftables 1.1.6 xuất ra. Bản
    đầu của fixture này dùng chuỗi "53"; verify so khớp chuỗi nên cũng xanh, và
    cả hai cùng sai theo cùng một cách. Chỉ test netns trên kernel thật mới
    tách được hai lỗi trùng dấu ấy ra.
    """
    items = [{"metainfo": {"version": "1.1.6"}}, {"table": {"family": "inet", "name": table}}]
    for name in chains:
        items.append({"chain": {"family": "inet", "table": table, "name": name,
                                "type": "filter", "hook": name, "prio": -150, "policy": policy}})
        expr = []
        if loopback:
            expr.append({"match": {"left": {"meta": {"key": "iif"}}, "op": "==", "right": "lo"}})
        items.append({"rule": {"family": "inet", "table": table, "chain": name,
                               "expr": expr + [{"verdict": {"accept": None}}]}})
        field = "saddr" if name == "input" else "daddr"
        items.append({"rule": {"family": "inet", "table": table, "chain": name, "expr": [
            {"match": {"left": {"payload": {"protocol": "ip", "field": field}},
                       "op": "==", "right": mgmt}},
            {"verdict": {"accept": None}}]}})
        if dns:
            items.append({"rule": {"family": "inet", "table": table, "chain": name, "expr": [
                {"match": {"left": {"payload": {"protocol": "udp", "field": "sport"}},
                           "op": "==", "right": dns_port}},
                {"verdict": {"accept": None}}]}})
    return json.dumps({"nftables": items})


def test_a_correct_ruleset_verifies():
    ok, reason = verify_isolation(_nft_json(), "192.168.1.10")
    assert ok is True, reason


def test_a_missing_table_fails_verification():
    """`nft` trả exit code 0 khi table không tồn tại nếu lệnh khác thành công —
    exit code không phải bằng chứng (mục 3.4)."""
    ok, reason = verify_isolation(json.dumps({"nftables": []}), "192.168.1.10")
    assert ok is False and "không tồn tại" in reason


def test_an_accept_policy_fails_verification():
    """Luật có đủ nhưng policy accept thì chẳng chặn gì cả."""
    ok, reason = verify_isolation(_nft_json(policy="accept"), "192.168.1.10")
    assert ok is False and "drop" in reason


def test_a_half_applied_ruleset_fails_verification():
    """Chỉ có chain input nghĩa là traffic đi RA vẫn thông."""
    ok, reason = verify_isolation(_nft_json(chains=("input",)), "192.168.1.10")
    assert ok is False and "output" in reason


def test_losing_the_management_exception_fails_verification():
    """Cách ly mà không chừa đường vào là hỏng nặng hơn không cách ly."""
    ok, reason = verify_isolation(_nft_json(mgmt="10.9.9.9"), "192.168.1.10")
    assert ok is False and "quản trị" in reason


def test_losing_loopback_fails_verification():
    ok, reason = verify_isolation(_nft_json(loopback=False), "192.168.1.10")
    assert ok is False and "loopback" in reason


def test_a_requested_dns_exception_must_actually_be_present():
    ok, reason = verify_isolation(_nft_json(dns=False), "192.168.1.10", preserve_dns=True)
    assert ok is False and "DNS" in reason
    ok, _ = verify_isolation(_nft_json(dns=True), "192.168.1.10", preserve_dns=True)
    assert ok is True


def test_garbage_output_fails_closed():
    for junk in ("", "not json", "{}", '{"nftables": "nope"}'):
        ok, _ = verify_isolation(junk, "192.168.1.10")
        assert ok is False


def test_rules_from_another_table_cannot_satisfy_verification():
    """Một table khác của người dùng tình cờ có luật accept không được tính là
    bằng chứng rằng cách ly đang hoạt động."""
    ok, _ = verify_isolation(_nft_json(table="some_other_table"), "192.168.1.10")
    assert ok is False


def test_isolation_present_reads_the_kernel_not_a_memory():
    assert isolation_present(_nft_json()) is True
    assert isolation_present(json.dumps({"nftables": []})) is False
    assert isolation_present("garbage") is False


def test_a_numeric_port_and_a_string_port_are_both_understood():
    """nftables xuất cổng là số nguyên; phiên bản khác có thể xuất chuỗi.

    Test này tồn tại vì một khác biệt đúng như thế đã lọt qua 23 test không cần
    root: verify so khớp chuỗi JSON thô, fixture bịa ra `"53"`, và cả hai cùng
    sai theo cùng một cách. Hậu quả thật là cách ly có ngoại lệ DNS bị coi là
    hỏng và tự gỡ ngay sau khi áp.
    """
    for port in (53, "53"):
        ok, reason = verify_isolation(_nft_json(dns=True, dns_port=port),
                                      "192.168.1.10", preserve_dns=True)
        assert ok is True, f"cổng dạng {type(port).__name__}: {reason}"


def test_the_pieces_of_an_exception_must_be_in_the_same_rule():
    """Một luật accept ở chỗ này cộng địa chỉ quản trị ở luật khác không phải
    là một ngoại lệ quản trị — gộp cả chain rồi tìm sẽ tính nhầm là đạt."""
    items = [{"metainfo": {}}, {"table": {"family": "inet", "name": ISOLATION_TABLE}}]
    for name in ("input", "output"):
        items.append({"chain": {"family": "inet", "table": ISOLATION_TABLE, "name": name,
                                "type": "filter", "hook": name, "policy": "drop"}})
        items.append({"rule": {"table": ISOLATION_TABLE, "chain": name, "expr": [
            {"match": {"left": {"meta": {"key": "iif"}}, "op": "==", "right": "lo"}},
            {"verdict": {"accept": None}}]}})
        # Địa chỉ quản trị có mặt, nhưng bị DROP chứ không phải accept.
        field = "saddr" if name == "input" else "daddr"
        items.append({"rule": {"table": ISOLATION_TABLE, "chain": name, "expr": [
            {"match": {"left": {"payload": {"protocol": "ip", "field": field}},
                       "op": "==", "right": "192.168.1.10"}},
            {"verdict": {"drop": None}}]}})
    ok, reason = verify_isolation(json.dumps({"nftables": items}), "192.168.1.10")
    assert ok is False and "quản trị" in reason
