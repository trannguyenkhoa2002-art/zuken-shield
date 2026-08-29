"""Cách ly endpoint bằng nftables — dựng ruleset và kiểm chứng hậu điều kiện.

KE-HOACH-SHIELD-2.0.md mục 0.2. Toàn bộ file này là hàm thuần: dựng chuỗi
ruleset và đọc JSON `nft` trả về. Không gọi subprocess, không cần root — nhờ
vậy phần khó nhất (luật có đúng không, verify có chặt không) test được trên
máy thường, còn phần cần root chỉ còn là hai lệnh `nft`.

Vì sao một `table` riêng, không dùng lại `table inet shield` của block_ip:

- `block_ip` là chặn MỘT địa chỉ; cách ly là chặn TẤT CẢ trừ vài ngoại lệ.
  Nhét cả hai vào một table nghĩa là gỡ cách ly có thể xoá nhầm luật chặn IP
  đang có hiệu lực, và ngược lại.
- Gỡ cách ly phải sạch tuyệt đối và idempotent. `nft delete table inet
  shield_isolation` xoá đúng và chỉ đúng phần cách ly, không đụng firewall của
  người dùng, không đụng table Shield khác.

Vì sao KHÔNG accept `ct state established,related`:

Cách ly một máy đang bị chiếm mà vẫn cho các kết nối đang mở chạy tiếp thì
phiên C2 của kẻ tấn công sống sót — đúng thứ cần cắt. Phiên quản trị không dựa
vào conntrack ở đây: nó được cho phép tường minh theo địa chỉ.
"""

from __future__ import annotations

import ipaddress
import json

ISOLATION_TABLE = "shield_isolation"
ISOLATION_FAMILY = "inet"

# Ưu tiên hook rất sớm. Với chain policy drop thì thứ tự không quyết định việc
# chặn (một drop ở bất kỳ chain nào cũng thắng), nhưng chạy sớm giúp các luật
# accept tường minh của Shield được xét trước khi bảng khác kịp đổi trạng thái
# gói tin, và làm ý định "đây là lớp ngoài cùng" rõ ràng khi ai đó đọc
# `nft list ruleset` lúc đang sự cố.
ISOLATION_PRIORITY = -150


def build_ruleset(management_ip: str, *, preserve_dns: bool = False) -> str:
    """Ruleset nftables cho một lần cách ly. Ném ValueError nếu IP không hợp lệ.

    `nft -f -` nạp cả file trong MỘT giao dịch: hoặc toàn bộ luật vào, hoặc
    không luật nào vào. Nhờ đó "áp một phần" gần như không xảy ra ở tầng kernel
    — nhưng caller vẫn phải verify, vì lệnh chạy xong không đồng nghĩa trạng
    thái đúng (mục 3.4).
    """
    address = ipaddress.ip_address(management_ip)
    if address.version != 4:
        raise ValueError("isolation is IPv4-only")
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("unsafe management address")
    ip = str(address)

    dns_in = "        udp sport 53 accept\n" if preserve_dns else ""
    dns_out = "        udp dport 53 accept\n" if preserve_dns else ""
    return f"""table {ISOLATION_FAMILY} {ISOLATION_TABLE} {{
    chain input {{
        type filter hook input priority {ISOLATION_PRIORITY}; policy drop;
        iif lo accept
        ip saddr {ip} accept
{dns_in}    }}
    chain output {{
        type filter hook output priority {ISOLATION_PRIORITY}; policy drop;
        oif lo accept
        ip daddr {ip} accept
{dns_out}    }}
}}
"""


def delete_ruleset() -> str:
    """Lệnh gỡ. Tách riêng để test đọc được, và để chỉ có MỘT chỗ biết tên table."""
    return f"delete table {ISOLATION_FAMILY} {ISOLATION_TABLE}"


def _rule_tokens(node, out: set[str] | None = None) -> set[str]:
    """Mọi khoá và giá trị vô hướng trong một luật, chuẩn hoá về chuỗi.

    Cần cả khoá lẫn giá trị vì nftables biểu diễn verdict là KHOÁ
    (`{"verdict": {"accept": null}}`) còn địa chỉ và cổng là GIÁ TRỊ. Chuẩn hoá
    về chuỗi để `53` và `"53"` là một — phiên bản nftables khác nhau xuất khác
    nhau, và sự khác biệt đó không nên là lý do cách ly tự gỡ.
    """
    if out is None:
        out = set()
    if isinstance(node, dict):
        for key, value in node.items():
            out.add(str(key))
            _rule_tokens(value, out)
    elif isinstance(node, list):
        for value in node:
            _rule_tokens(value, out)
    elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
        out.add(str(node))
    return out


class VerificationFailed(Exception):
    """Hậu điều kiện không khớp trạng thái hệ thống thật."""


def verify_isolation(nft_json: str, management_ip: str, *, preserve_dns: bool = False) -> tuple[bool, str]:
    """Đọc `nft -j list table inet shield_isolation` và trả (đạt, lý do).

    Đây là bước biến `ok=True` từ lời hứa thành sự kiện: chỉ trả True khi kernel
    thật sự đang giữ đúng bộ luật mong đợi. Exit code 0 của `nft` KHÔNG đủ.
    """
    try:
        parsed = json.loads(nft_json)
        items = parsed["nftables"]
    except (ValueError, KeyError, TypeError):
        return False, "không đọc được ruleset nftables"

    tables, chains, rules = [], {}, []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "table" in item and item["table"].get("name") == ISOLATION_TABLE:
            tables.append(item["table"])
        elif "chain" in item and item["chain"].get("table") == ISOLATION_TABLE:
            chains[item["chain"].get("name")] = item["chain"]
        elif "rule" in item and item["rule"].get("table") == ISOLATION_TABLE:
            rules.append(item["rule"])

    if not tables:
        return False, f"table {ISOLATION_FAMILY} {ISOLATION_TABLE} không tồn tại"

    for name in ("input", "output"):
        chain = chains.get(name)
        if chain is None:
            return False, f"thiếu chain {name}"
        if chain.get("policy") != "drop":
            return False, f"chain {name} có policy {chain.get('policy')!r}, phải là 'drop'"
        if chain.get("hook") != name:
            return False, f"chain {name} không gắn vào hook {name}"

    # Đường quản trị PHẢI còn: cách ly mà không chừa đường vào là hỏng nặng hơn
    # không cách ly — không ai sửa được máy nữa, kể cả người đã bấm nút.
    #
    # Đọc theo CẤU TRÚC, không so khớp chuỗi JSON thô. Bản đầu so chuỗi và tin
    # rằng cổng 53 xuất hiện dưới dạng `"53"`; nftables thật xuất số nguyên
    # `53`, nên ngoại lệ DNS có thật vẫn bị coi là thiếu và cách ly tự gỡ ngay
    # sau khi áp. 23 test không cần root đều xanh vì fixture của chúng dùng
    # đúng định dạng bịa ra. Chỉ kernel thật mới bắt được.
    per_chain: dict[str, list[set[str]]] = {"input": [], "output": []}
    for rule in rules:
        chain_name = rule.get("chain")
        if chain_name in per_chain:
            per_chain[chain_name].append(_rule_tokens(rule.get("expr", [])))

    def has_rule(chain_name: str, *required: str) -> bool:
        """Mọi mẩu phải nằm trong CÙNG một luật.

        Gộp cả chain rồi tìm nghĩa là một luật `accept` bất kỳ cộng với địa chỉ
        quản trị xuất hiện ở một luật `drop` khác sẽ được tính là đạt.
        """
        return any(set(required) <= tokens for tokens in per_chain[chain_name])

    for name, field in (("input", "saddr"), ("output", "daddr")):
        if not has_rule(name, management_ip, field, "accept"):
            return False, f"chain {name} không có luật accept cho địa chỉ quản trị {management_ip}"
        if not has_rule(name, "lo", "accept"):
            return False, f"chain {name} không giữ loopback — guardian và IPC cục bộ sẽ đứt"
        if preserve_dns and not has_rule(name, "53", "accept"):
            return False, f"chain {name} thiếu ngoại lệ DNS đã yêu cầu"

    return True, "đã kiểm chứng: policy drop trên cả hai hook, loopback và đường quản trị còn nguyên"


def isolation_present(nft_json: str) -> bool:
    """Table cách ly có đang tồn tại không — dùng cho phục hồi sau crash."""
    try:
        items = json.loads(nft_json)["nftables"]
    except (ValueError, KeyError, TypeError):
        return False
    return any(isinstance(i, dict) and "table" in i and i["table"].get("name") == ISOLATION_TABLE
               for i in items)
