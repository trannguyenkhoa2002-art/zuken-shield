"""Bóc lớp gói tin bằng scapy -> quan sát có cấu trúc.

ĐÂY LÀ NƠI DUY NHẤT trong toàn bộ cây mã được phép `import scapy`. Một bài test
bất biến quét lõi Shield để bảo đảm điều đó không trôi đi.

Mỗi hàm nhận một gói scapy và trả về `(observation, payload)` hoặc `None`. Chúng
THUẦN theo nghĩa không I/O, không trạng thái toàn cục — nên test được bằng gói
giả, không cần quyền root và không cần card mạng.
"""

from __future__ import annotations

# BPF filter áp ở tầng kernel: gói không khớp không bao giờ tới Python.
BPF_ARP = "arp or icmp or icmp6 or (udp and (port 67 or port 68))"
BPF_CONN = "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) != 0)"
BPF_DNS = "udp and dst port 53"


def safe_dhcp_options(raw_options) -> dict:
    """Tuỳ chọn DHCP -> dict. scapy có thể trả entry KHÔNG phải tuple 2 phần tử.

    Chuyển nguyên vẹn từ lõi sang đây cùng lý do như phần còn lại: nó bóc cấu
    trúc của scapy, nên nó thuộc về phía có scapy.
    """
    out: dict = {}
    for entry in raw_options or ():
        if isinstance(entry, (tuple, list)) and len(entry) == 2:
            key, value = entry
            if isinstance(key, str):
                out[key] = value
    return out


def from_arp_packet(pkt) -> tuple[str, dict] | None:
    from scapy.all import ARP, BOOTP, DHCP, ICMP, IP, ICMPv6ND_NA

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.op not in (1, 2):
            return None
        kind = "arp_reply" if arp.op == 2 else "arp_request"
        return kind, {"ip": str(arp.psrc), "mac": str(arp.hwsrc).lower()}

    if pkt.haslayer(ICMPv6ND_NA):
        na = pkt[ICMPv6ND_NA]
        mac = getattr(getattr(na, "payload", None), "lladdr", None)
        if mac:
            return "ndp_advertisement", {"ip": str(na.tgt), "mac": str(mac).lower()}
        return None

    if pkt.haslayer(ICMP) and pkt[ICMP].type == 5 and pkt.haslayer(IP):
        return "icmp_redirect", {"src_ip": str(pkt[IP].src)}

    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP) and pkt.haslayer(IP):
        options = safe_dhcp_options(pkt[DHCP].options)
        if options.get("message-type") == 2:            # DHCPOFFER
            server = options.get("server_id") or pkt[IP].src
            return "dhcp_offer", {"server_ip": str(server), "ip": str(pkt[IP].src)}
    return None


def from_tcp_packet(pkt, local_addresses: set[str]) -> tuple[str, dict] | None:
    from scapy.all import IP, TCP

    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return None
    tcp, ip = pkt[TCP], pkt[IP]
    flags = int(tcp.flags)
    syn, ack = bool(flags & 0x02), bool(flags & 0x10)
    destination = str(ip.dst)
    if destination not in local_addresses:
        return None                                     # chỉ quan tâm gói TỚI máy này
    if syn and not ack:
        return "tcp_syn", {"src_ip": str(ip.src), "dst_port": int(tcp.dport)}
    if ack and not syn:
        return "tcp_ack", {"src_ip": str(ip.src), "dst_port": int(tcp.dport)}
    return None


def from_dns_packet(pkt) -> tuple[str, dict] | None:
    from scapy.all import IP, UDP

    if not (pkt.haslayer(UDP) and pkt.haslayer(IP)):
        return None
    if int(pkt[UDP].dport) != 53:
        return None
    return "dns_query_out", {"server_ip": str(pkt[IP].dst)}


def packet_length(pkt) -> int:
    return int(len(pkt))
