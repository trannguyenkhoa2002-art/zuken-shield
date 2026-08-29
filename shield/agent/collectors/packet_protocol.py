"""Hợp đồng IPC, PHÍA LÕI — bộ kiểm đầu vào không tin cậy.

Bản sao độc lập với `packet_helper/protocol.py`, và điều đó là CỐ Ý: lõi
Apache-2.0 không được import gói helper (helper phụ thuộc scapy, GPL-2.0), còn
helper không được import lõi. Hai chiều đều bị test cấm.

Hai bản sao có nguy cơ trôi khỏi nhau, nên có một bài test so từng trường của
chúng và đỏ ngay khi lệch. Đó là cái giá đã cân nhắc: một phụ thuộc vòng qua
ranh giới giấy phép thì tệ hơn hai bản sao được canh bằng test.

Hợp đồng gốc:

Một dòng JSON một quan sát (NDJSON). Không pickle, không object Python tuỳ ý,
không kênh lệnh — helper chỉ nói, lõi chỉ nghe.

Lõi coi MỌI thứ đến từ đây là dữ liệu KHÔNG TIN CẬY: nó chạy bằng root, đọc gói
tin từ mạng, và một gói tin dị dạng là thứ kẻ tấn công gửi được. Vì vậy schema ở
đây được ĐÓNG: loại quan sát đóng, khoá đóng, độ dài có trần, số có khoảng.
"""

from __future__ import annotations

import re

SCHEMA_VERSION = 1

# Đường dẫn CỐ ĐỊNH. Không dò PATH, không biến môi trường: một socket tìm được
# bằng cách dò là một socket giả mạo được.
SOCKET_PATH = "/run/shield/packet-collector.sock"

# Loại quan sát ĐÓNG. Mỗi cái ánh xạ 1-1 sang `(source, kind)` của Event lõi,
# nên helper không thể phát ra một loại sự kiện mà lõi chưa biết.
OBSERVATIONS: dict[str, tuple[str, str]] = {
    "arp_reply": ("arp_sniffer", "arp_reply"),
    "arp_request": ("arp_sniffer", "arp_request"),
    "ndp_advertisement": ("arp_sniffer", "ndp_advertisement"),
    "icmp_redirect": ("arp_sniffer", "icmp_redirect"),
    "dhcp_offer": ("arp_sniffer", "dhcp_offer"),
    "tcp_syn": ("conn_watch", "tcp_syn"),
    "tcp_ack": ("conn_watch", "tcp_ack"),
    "dns_query_out": ("dns_watch", "dns_query_out"),
}

# Trần. Một helper bị chiếm quyền không được biến thành vòi bơm dữ liệu.
MAX_LINE_BYTES = 4096
MAX_PAYLOAD_KEYS = 12
MAX_STRING_CHARS = 256
MAX_LIST_ITEMS = 16

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]{2,45}$")
_MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")

# Khoá nào phải qua bộ kiểm nào. Khoá lạ bị BỎ, không được đi tiếp "phòng khi".
_IP_KEYS = frozenset({"ip", "src_ip", "dst_ip", "server_ip", "gateway_ip"})
_MAC_KEYS = frozenset({"mac", "observed_mac", "baseline_mac"})
_INT_KEYS = frozenset({"dst_port", "src_port", "bytes_per_s", "count"})
_STR_KEYS = frozenset({"interface", "hostname", "vendor", "reason"})
_LIST_KEYS = frozenset({"known", "macs", "ports"})
_BOOL_KEYS = frozenset({"local", "outbound"})

ALLOWED_KEYS = (_IP_KEYS | _MAC_KEYS | _INT_KEYS | _STR_KEYS | _LIST_KEYS
                | _BOOL_KEYS)


def valid_ip(value) -> bool:
    text = str(value)
    if _IPV4.match(text):
        return all(0 <= int(part) <= 255 for part in text.split("."))
    return bool(_IPV6.match(text)) and text.count(":") >= 2


def valid_mac(value) -> bool:
    return bool(_MAC.match(str(value).lower()))


def clean_payload(raw) -> dict | None:
    """Payload thô -> payload AN TOÀN, hoặc `None` nếu không cứu được.

    Bỏ khoá lạ thay vì từ chối cả bản tin: một phiên bản helper mới hơn có thể
    thêm trường, và lõi cũ vẫn phải dùng được phần nó hiểu. Nhưng một GIÁ TRỊ
    sai kiểu thì loại cả bản tin — đó là dấu hiệu hỏng, không phải mở rộng.
    """
    if not isinstance(raw, dict) or len(raw) > MAX_PAYLOAD_KEYS:
        return None
    out: dict = {}
    for key, value in raw.items():
        if key not in ALLOWED_KEYS:
            continue
        if key in _IP_KEYS:
            if not valid_ip(value):
                return None
            out[key] = str(value)
        elif key in _MAC_KEYS:
            if not valid_mac(value):
                return None
            out[key] = str(value).lower()
        elif key in _INT_KEYS:
            if isinstance(value, bool) or not isinstance(value, int):
                return None
            if not 0 <= value <= 2**32:
                return None
            out[key] = value
        elif key in _BOOL_KEYS:
            if not isinstance(value, bool):
                return None
            out[key] = value
        elif key in _STR_KEYS:
            if not isinstance(value, str) or len(value) > MAX_STRING_CHARS:
                return None
            out[key] = value
        elif key in _LIST_KEYS:
            if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
                return None
            items = []
            for item in value:
                if isinstance(item, bool) or isinstance(item, int):
                    if not 0 <= int(item) <= 2**32:
                        return None
                    items.append(int(item))
                elif isinstance(item, str) and len(item) <= MAX_STRING_CHARS:
                    items.append(item)
                else:
                    return None
            out[key] = items
    return out
