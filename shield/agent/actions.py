"""Allowlist hành động hệ thống (KE-HOACH-SHIELD.md mục 3).

Nguyên tắc: agent chỉ nhận action_id từ allowlist cứng, không bao giờ nhận
chuỗi lệnh từ UI, luôn validate IP/MAC bằng regex trước khi build subprocess
(không `shell=True`).

`block_ip`/`block_mac` dùng set nftables có `flags timeout` — kernel tự xoá
entry sau TTL, không cần agent tự nhớ dọn dẹp (mục 6 rủi ro "Chặn nhầm chính
thiết bị của mình" -> tự động hết hạn sau 24h). Mọi rule nằm trong
`table inet shield` riêng, không đụng firewall khác — `nft delete table inet
shield` là sạch hoàn toàn.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
from pathlib import Path

from shield.security import isolation

logger = logging.getLogger("shield.actions")

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

BLOCK_TTL = "24h"

# Ngưỡng rate-limit: gói vượt quá mức này từ MỘT địa chỉ bị bỏ. Đủ rộng để một
# máy dùng bình thường không chạm tới, đủ hẹp để chặn một lượt quét cổng hay
# một lượt dò mật khẩu.
RATE_LIMIT = "50/second"
RATE_LIMIT_TTL = "1h"

_NFT_RULESET = """
table inet shield {
    set blocked_ips { type ipv4_addr; flags timeout; }
    set blocked_macs { type ether_addr; flags timeout; }
    set ratelimited_ips { type ipv4_addr; flags timeout; }
    chain input {
        type filter hook input priority filter; policy accept;
        ip saddr @blocked_ips drop
        ether saddr @blocked_macs drop
        ip saddr @ratelimited_ips limit rate over """ + RATE_LIMIT + """ drop
    }
    chain output {
        type filter hook output priority filter; policy accept;
        ip daddr @blocked_ips drop
    }
}
"""


async def pin_gateway_arp(gw_ip: str, gw_mac: str, interface: str) -> tuple[bool, str]:
    """`ip neigh replace <gw_ip> lladdr <gw_mac> dev <interface> nud permanent`.

    Sau lệnh này, ARP spoof không lừa được máy mình cho gateway nữa — kernel
    sẽ bỏ qua mọi ARP reply claim lại IP này. Reversible: `ip neigh del <gw_ip>
    dev <interface>`. `dev` là bắt buộc trên iproute2 hiện đại — thiếu sẽ báo
    lỗi "Device and destination are required arguments" (phát hiện lúc test).
    """
    if not _IP_RE.match(gw_ip):
        return False, f"IP không hợp lệ: {gw_ip!r}"
    if not _MAC_RE.match(gw_mac):
        return False, f"MAC không hợp lệ: {gw_mac!r}"
    if not interface:
        return False, "Không xác định được interface để pin ARP"

    cmd = [
        "ip", "neigh", "replace", gw_ip, "lladdr", gw_mac,
        "dev", interface, "nud", "permanent",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode(errors="ignore").strip()
        logger.error("pin_gateway_arp thất bại: %s", err)
        return False, err

    logger.info("Đã pin ARP gateway %s -> %s (permanent)", gw_ip, gw_mac)
    return True, "OK"


async def _run(cmd: list[str]) -> tuple[bool, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        return False, stderr.decode(errors="ignore").strip()
    return True, "OK"


async def ensure_shield_table() -> tuple[bool, str]:
    """Tạo `table inet shield` nếu chưa có — idempotent, an toàn gọi nhiều lần.

    Trả về sớm khi table đã tồn tại là ĐÚNG cho việc tạo table, nhưng sai cho
    việc thêm một thành phần mới vào một bản cài cũ: máy đã chạy 1.x có table
    này rồi, nên `set ratelimited_ips` và luật dùng nó sẽ không bao giờ được
    tạo, và tính năng mới im lặng không hoạt động trên đúng những máy đã dùng
    lâu nhất. Vì vậy đường "đã tồn tại" vẫn phải đi qua `_ensure_rate_limit`.
    """
    check = await asyncio.create_subprocess_exec(
        "nft", "list", "table", "inet", "shield",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await check.wait()
    if check.returncode == 0:
        return await _ensure_rate_limit()

    proc = await asyncio.create_subprocess_exec(
        "nft", "-f", "-",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate(_NFT_RULESET.encode())
    if proc.returncode != 0:
        err = stderr.decode(errors="ignore").strip()
        logger.error("Tạo table inet shield thất bại: %s", err)
        return False, err
    logger.info("Đã tạo table inet shield (blocked_ips/blocked_macs/ratelimited_ips)")
    return True, "OK"


async def _ensure_rate_limit() -> tuple[bool, str]:
    """Bổ sung set và luật rate-limit vào một table đã có sẵn.

    `nft add set` trên set đã tồn tại là no-op. `nft add rule` thì KHÔNG —
    nó nối thêm một luật trùng mỗi lần gọi, và sau vài lần khởi động lại chain
    sẽ đầy những luật giống hệt nhau. Nên phải đọc chain trước.
    """
    ok, _ = await _run(["nft", "add", "set", "inet", "shield", "ratelimited_ips",
                        "{ type ipv4_addr; flags timeout; }"])
    if not ok:
        return True, "đã tồn tại"   # không tạo được set thì cũng không thêm luật
    ok, listing = await _run_capture(["nft", "list", "chain", "inet", "shield", "input"])
    if ok and "@ratelimited_ips" in listing:
        return True, "đã tồn tại"
    added, message = await _run([
        "nft", "add", "rule", "inet", "shield", "input",
        "ip", "saddr", "@ratelimited_ips", "limit", "rate", "over", RATE_LIMIT, "drop",
    ])
    if added:
        logger.info("Đã bổ sung luật rate-limit vào table inet shield đã có sẵn")
    return True, "OK" if added else message


async def block_ip(ip: str) -> tuple[bool, str]:
    """Thêm `ip` vào set `blocked_ips`, tự hết hạn sau BLOCK_TTL — dùng khi
    thiết bị lạ hung hăng (mục 3 kế hoạch)."""
    if not _IP_RE.match(ip):
        return False, f"IP không hợp lệ: {ip!r}"
    ok, msg = await ensure_shield_table()
    if not ok:
        return False, msg
    ok, msg = await _run(
        ["nft", "add", "element", "inet", "shield", "blocked_ips", f"{{ {ip} timeout {BLOCK_TTL} }}"]
    )
    if ok:
        logger.info("Đã chặn IP %s (tự hết hạn sau %s)", ip, BLOCK_TTL)
    else:
        logger.error("block_ip %s thất bại: %s", ip, msg)
    return ok, msg


async def unblock_ip(ip: str) -> tuple[bool, str]:
    if not _IP_RE.match(ip):
        return False, f"IP không hợp lệ: {ip!r}"
    ok, msg = await _run(["nft", "delete", "element", "inet", "shield", "blocked_ips", f"{{ {ip} }}"])
    if ok:
        logger.info("Đã gỡ chặn IP %s", ip)
    return ok, msg


async def block_mac(mac: str) -> tuple[bool, str]:
    """Thêm `mac` vào set `blocked_macs` — dùng khi kẻ tấn công đổi IP nhưng
    giữ nguyên MAC (mục 3 kế hoạch)."""
    if not _MAC_RE.match(mac):
        return False, f"MAC không hợp lệ: {mac!r}"
    ok, msg = await ensure_shield_table()
    if not ok:
        return False, msg
    ok, msg = await _run(
        ["nft", "add", "element", "inet", "shield", "blocked_macs", f"{{ {mac} timeout {BLOCK_TTL} }}"]
    )
    if ok:
        logger.info("Đã chặn MAC %s (tự hết hạn sau %s)", mac, BLOCK_TTL)
    else:
        logger.error("block_mac %s thất bại: %s", mac, msg)
    return ok, msg


async def rate_limit_ip(ip: str) -> tuple[bool, str]:
    """Giới hạn tốc độ gói từ `ip` thay vì chặn hẳn.

    Đây là bậc thang giữa "không làm gì" và "chặn": một địa chỉ đang quét cổng
    bị làm chậm tới mức vô dụng, nhưng nếu Shield đoán sai thì người dùng thật
    ở địa chỉ đó vẫn làm việc được — chậm, chứ không đứt.
    """
    if not _IP_RE.match(ip):
        return False, f"IP không hợp lệ: {ip!r}"
    ok, msg = await ensure_shield_table()
    if not ok:
        return False, msg
    ok, msg = await _run(["nft", "add", "element", "inet", "shield", "ratelimited_ips",
                          f"{{ {ip} timeout {RATE_LIMIT_TTL} }}"])
    if ok:
        logger.info("Đã giới hạn tốc độ %s (%s, tự hết hạn sau %s)",
                    ip, RATE_LIMIT, RATE_LIMIT_TTL)
    else:
        logger.error("rate_limit_ip %s thất bại: %s", ip, msg)
    return ok, msg


async def unrate_limit_ip(ip: str) -> tuple[bool, str]:
    if not _IP_RE.match(ip):
        return False, f"IP không hợp lệ: {ip!r}"
    ok, msg = await _run(["nft", "delete", "element", "inet", "shield",
                          "ratelimited_ips", f"{{ {ip} }}"])
    if ok:
        logger.info("Đã gỡ giới hạn tốc độ %s", ip)
    return ok, msg


async def unblock_mac(mac: str) -> tuple[bool, str]:
    if not _MAC_RE.match(mac):
        return False, f"MAC không hợp lệ: {mac!r}"
    ok, msg = await _run(["nft", "delete", "element", "inet", "shield", "blocked_macs", f"{{ {mac} }}"])
    if ok:
        logger.info("Đã gỡ chặn MAC %s", mac)
    return ok, msg


# --- Tự kiểm tra bảo mật (mục "công cụ chủ động") — chỉ liệt kê cổng mở +
# phân loại rủi ro, KHÔNG khai thác gì (đúng ranh giới mục 7 kế hoạch: không
# quét khai thác lỗ hổng). `nmap -sV` chỉ hỏi banner dịch vụ, không chạy NSE
# script tấn công. ---

# Cổng "nguy hiểm": lịch sử là cửa vào của mã độc/nghe trộm nếu mở ra LAN mà
# không chủ đích (Telnet không mã hoá, SMB từng bị khai thác EternalBlue,
# RDP/VNC/X11 điều khiển máy từ xa...).
_DANGER_PORTS = {21, 23, 135, 139, 445, 512, 513, 514, 1433, 3389, 5900, 6000}
# Cổng "nên xem lại": hữu ích nhưng đáng kiểm tra đã cấu hình đúng chưa
# (SSH/HTTP quản trị/DB thường chỉ nên nghe trên localhost hoặc VPN).
_CAUTION_PORTS = {22, 80, 443, 3306, 5432, 8080, 8443, 27017}

_PORT_LINE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")


def classify_port_risk(port: int) -> str:
    if port in _DANGER_PORTS:
        return "danger"
    if port in _CAUTION_PORTS:
        return "caution"
    return "safe"


# Gợi ý CVE offline — bảng tĩnh, không gọi API/NVD sống, không kiểm tra
# version cụ thể của banner (điều đó cần crawl dữ liệu CVE liên tục, ngoài
# phạm vi đã chọn: "chỉ liệt kê để người dùng tự tra cứu thêm, không khai
# thác, không phụ thuộc mạng ngoài"). Chỉ nhắc CVE/lỗ hổng nổi tiếng thường
# gắn với cổng — người dùng tự đối chiếu version banner nmap trả về.
_CVE_HINTS: dict[int, list[dict[str, str]]] = {
    21: [{"cve": "CVE-2011-2523", "note": "Backdoor vsftpd 2.3.4 — kiểm tra version FTP nếu cũ."}],
    23: [{"cve": "-", "note": "Telnet truyền cleartext — nên tắt, dùng SSH thay thế."}],
    139: [{"cve": "CVE-2017-0144", "note": "EternalBlue (SMBv1) — kiểm tra đã vá/tắt SMBv1 chưa."}],
    445: [{"cve": "CVE-2017-0144", "note": "EternalBlue (SMBv1) — kiểm tra đã vá/tắt SMBv1 chưa."}],
    512: [{"cve": "-", "note": "rexec cleartext — dịch vụ cũ, nên tắt nếu không dùng."}],
    513: [{"cve": "-", "note": "rlogin cleartext — dịch vụ cũ, nên tắt nếu không dùng."}],
    514: [{"cve": "-", "note": "rsh cleartext — dịch vụ cũ, nên tắt nếu không dùng."}],
    1433: [{"cve": "CVE-2008-0107", "note": "MS SQL Server có lịch sử nhiều lỗ hổng — kiểm tra bản vá."}],
    3389: [{"cve": "CVE-2019-0708", "note": "BlueKeep (RDP) — kiểm tra bản vá Windows nếu RDP mở ra ngoài."}],
    5900: [{"cve": "-", "note": "VNC không mã hoá mặc định — nên bọc qua VPN/SSH tunnel."}],
    6000: [{"cve": "-", "note": "X11 mở ra mạng có thể bị chiếm hiển thị — nên chỉ bind localhost."}],
}


# Khuyến nghị hành động cụ thể theo cổng — trả lời câu "thấy rồi thì làm gì".
# Cố tình là lời khuyên cấu hình, KHÔNG phải lệnh tự chạy: Shield không tự
# tắt dịch vụ của người dùng, chỉ nói nên làm gì để họ tự quyết.
_PORT_ADVICE: dict[int, str] = {
    21: "FTP không mã hoá — chuyển sang SFTP/FTPS, hoặc tắt nếu không dùng.",
    22: "SSH: tắt đăng nhập bằng mật khẩu (chỉ dùng key), không mở ra Internet.",
    23: "Telnet gửi mật khẩu dạng thô — nên tắt hẳn, dùng SSH thay thế.",
    80: "HTTP không mã hoá — nếu là trang quản trị, chỉ nên bind 127.0.0.1.",
    135: "RPC Windows — không nên mở ra ngoài LAN, chặn ở firewall.",
    139: "NetBIOS/SMBv1 — tắt SMBv1, chỉ chia sẻ trong LAN tin cậy.",
    443: "HTTPS: kiểm tra chứng chỉ còn hạn và cấu hình TLS không dùng bản cũ.",
    445: "SMB: tắt SMBv1, đặt mật khẩu chia sẻ, không mở ra Internet.",
    512: "rexec là dịch vụ cũ không mã hoá — nên tắt.",
    513: "rlogin là dịch vụ cũ không mã hoá — nên tắt.",
    514: "rsh là dịch vụ cũ không mã hoá — nên tắt.",
    1433: "MS SQL: chỉ nghe trên localhost/VPN, không mở ra LAN nếu không cần.",
    3306: "MySQL: bind 127.0.0.1 trừ khi thật sự cần truy cập từ máy khác.",
    3389: "RDP: bật NLA, dùng VPN thay vì mở thẳng, đặt mật khẩu mạnh.",
    5432: "PostgreSQL: bind 127.0.0.1, kiểm tra pg_hba.conf không cho phép trust.",
    5900: "VNC không mã hoá mặc định — bọc qua SSH tunnel hoặc VPN.",
    6000: "X11 mở ra mạng có thể bị chiếm màn hình — chỉ nên bind localhost.",
    8080: "Cổng web phụ thường là trang quản trị — kiểm tra có cần mở ra LAN không.",
    8443: "HTTPS phụ thường là trang quản trị — hạn chế truy cập theo IP nguồn.",
    27017: "MongoDB: bật xác thực, bind 127.0.0.1 — Mongo mở ra ngoài là lỗi kinh điển.",
}


def advice_for_port(port: int) -> str:
    """Khuyến nghị cấu hình cho 1 cổng mở. Chuỗi rỗng nếu không có khuyến
    nghị sẵn — không có nghĩa cổng đó an toàn."""
    return _PORT_ADVICE.get(port, "")


def cve_hints_for_port(port: int) -> list[dict[str, str]]:
    """Gợi ý CVE tĩnh (offline, không gọi mạng ngoài) cho 1 cổng đang mở.
    Trả [] nếu cổng không nằm trong bảng gợi ý — không có nghĩa là an toàn,
    chỉ là không có gợi ý sẵn để tra cứu thêm.
    """
    return _CVE_HINTS.get(port, [])


def _parse_nmap_sV(output: str) -> list[dict]:
    ports = []
    for line in output.splitlines():
        m = _PORT_LINE_RE.match(line.strip())
        if not m:
            continue
        port, proto, service, version = m.groups()
        port_num = int(port)
        ports.append(
            {
                "port": port_num,
                "proto": proto,
                "service": service,
                "version": (version or "").strip(),
                "risk": classify_port_risk(port_num),
                "cve_hints": cve_hints_for_port(port_num),
                "advice": advice_for_port(port_num),
            }
        )
    return ports


async def self_port_scan(host: str) -> tuple[bool, str, list[dict]]:
    """`nmap -sV -T4 --host-timeout 30s <host>` — chỉ hỏi banner dịch vụ đang
    chạy, không chạy exploit/NSE tấn công. Validate host bằng regex IP hoặc
    hostname trước khi build subprocess (không tin input từ UI/lịch quét).
    """
    if not (_IP_RE.match(host) or _HOSTNAME_RE.match(host)):
        return False, f"Host không hợp lệ: {host!r}", []

    cmd = ["nmap", "-sV", "-T4", "--host-timeout", "30s", host]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode(errors="ignore").strip()
        logger.error("self_port_scan %s thất bại: %s", host, err)
        return False, err, []

    ports = _parse_nmap_sV(stdout.decode(errors="ignore"))
    logger.info("self_port_scan %s: %d cổng mở", host, len(ports))
    return True, "OK", ports


# --- Quét dải mạng được cấp phép (ngoài mạng nhà, ví dụ mạng công ty được
# ủy quyền) — KE-HOACH-SHIELD.md mục 7 vẫn cấm khai thác/tấn công, nên
# range_discovery_scan chỉ dò host sống (-sn), không quét cổng. Quét cổng
# từng host tái dùng self_port_scan (banner-only, -sV) ở agent/__main__.py.
# Giới hạn 1024 địa chỉ (~/22) để một CIDR gõ nhầm không quét ra cả /8. ---

_MAX_RANGE_ADDRESSES = 1024


def validate_authorized_cidr(cidr: str) -> tuple[bool, str]:
    """Trả (True, cidr_chuẩn_hoá) nếu hợp lệ, ngược lại (False, lý do)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return False, f"CIDR không hợp lệ: {e}"
    if net.num_addresses > _MAX_RANGE_ADDRESSES:
        return False, (
            f"Dải quá lớn ({net.num_addresses} địa chỉ) — tối đa {_MAX_RANGE_ADDRESSES} "
            "(~/22). Chia nhỏ ra thành nhiều dải rồi cấp phép từng cái."
        )
    return True, str(net)


async def range_discovery_scan(cidr: str) -> tuple[bool, str, list[dict]]:
    """`nmap -sn <cidr>` — chỉ dò host sống, không quét cổng/dịch vụ. `cidr`
    PHẢI đã qua validate_authorized_cidr() và đối chiếu với
    store.list_authorized_ranges() ở agent/__main__.py trước khi gọi hàm
    này — hàm này không tự kiểm tra cấp phép."""
    proc = await asyncio.create_subprocess_exec(
        "nmap", "-sn", cidr, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode(errors="ignore").strip()
        logger.error("range_discovery_scan %s thất bại: %s", cidr, err)
        return False, err, []

    from shield.agent.collectors.discovery import _parse_nmap_sn

    hosts = _parse_nmap_sn(stdout.decode(errors="ignore"))
    logger.info("range_discovery_scan %s: %d host sống", cidr, len(hosts))
    return True, "OK", hosts


def default_snapshot_dir() -> Path:
    env = os.environ.get("SHIELD_SNAPSHOT_DIR")
    if env:
        return Path(env)
    prod_candidate = Path("/var/lib/shield/snapshots")
    if prod_candidate.parent.exists() and os.access(prod_candidate.parent, os.W_OK):
        return prod_candidate
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return data_home / "shield" / "snapshots"


async def snapshot_state() -> tuple[bool, str]:
    """Lưu `ip neigh`, `ss -tunp`, `nft list ruleset` vào 1 file — chụp hiện
    trạng để điều tra sau, đặc biệt hữu ích chạy TRƯỚC khi block_* (chặn rồi
    thì hết dấu vết, mục 2.5 kế hoạch)."""
    snap_dir = default_snapshot_dir()
    snap_dir.mkdir(parents=True, exist_ok=True)
    path = snap_dir / f"snapshot-{int(time.time())}.txt"

    sections: list[str] = []
    for title, cmd in [
        ("ip neigh", ["ip", "neigh"]),
        ("ss -tunp", ["ss", "-tunp"]),
        ("nft list ruleset", ["nft", "list", "ruleset"]),
    ]:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, err = await proc.communicate()
        sections.append(
            f"=== {title} ===\n{out.decode(errors='ignore')}\n{err.decode(errors='ignore')}"
        )

    path.write_text("\n\n".join(sections))
    logger.info("Đã lưu snapshot hiện trạng: %s", path)
    return True, str(path)


# --- Xem mật khẩu WiFi đã lưu trên CHÍNH máy này (KE-HOACH-SHIELD.md mục 7:
# chỉ đọc thông tin đã có, không dò/bẻ mật khẩu mạng khác). NetworkManager
# lưu secret trong file cấu hình mà chỉ root đọc được — agent chạy dưới
# systemd (root) nên đọc lại được qua `nmcli -s`, KHÔNG có bất kỳ hành vi
# tấn công mạng nào (không sniff handshake, không brute-force, không kết nối
# tới mạng khác). Chỉ trả về những gì NetworkManager của MÁY NÀY đã tự lưu. ---


async def _run_capture(cmd: list[str]) -> tuple[bool, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        return False, stderr.decode(errors="ignore").strip()
    return True, stdout.decode(errors="ignore")


_WIFI_CONN_TYPES = ("802-11-wireless", "wifi")


def _filter_wifi_connection_names(out: str) -> list[str]:
    """Từ output `nmcli -t -f NAME,TYPE connection show`, lọc ra tên các kết
    nối kiểu WiFi. Tách riêng thành hàm thuần để test không cần gọi nmcli
    thật (giống safe_dhcp_options — nơi từng crash vì input thực tế lệch
    giả định)."""
    names: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name, conn_type = parts[0], parts[1]
        if conn_type in _WIFI_CONN_TYPES:
            names.append(name)
    return names


async def list_saved_wifi_passwords() -> tuple[bool, str, list[dict]]:
    """Liệt kê SSID + mật khẩu các mạng WiFi mà NetworkManager của MÁY NÀY đã
    lưu sẵn (do người dùng từng tự kết nối và tick "Remember"). Không quét,
    không nghe lén handshake, không dò mật khẩu mạng nào khác — chỉ đọc lại
    secret NetworkManager đã có trong `nmcli -s`, tương đương việc người
    dùng tự mở "Wi-Fi Settings" trên máy mình.
    """
    ok, out = await _run_capture(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    if not ok:
        logger.error("list_saved_wifi_passwords: không liệt kê được connection (%s)", out)
        return False, out, []

    networks: list[dict] = []
    for name in _filter_wifi_connection_names(out):
        ok_ssid, ssid_out = await _run_capture(
            ["nmcli", "-s", "-g", "802-11-wireless.ssid", "connection", "show", name]
        )
        ssid = ssid_out.strip() if ok_ssid and ssid_out.strip() else name

        ok_psk, psk_out = await _run_capture(
            ["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", name]
        )
        password = psk_out.strip() if ok_psk else ""

        networks.append({"name": name, "ssid": ssid, "password": password})

    logger.info("list_saved_wifi_passwords: %d mạng WiFi đã lưu", len(networks))
    return True, "OK", networks


# --- Cách ly endpoint (KE-HOACH-SHIELD-2.0.md mục 0.2) ---
#
# Đường đi: ResponseExecutor -> PrivilegedClient -> helper -> hai hàm dưới đây.
# Luật nằm trong `table inet shield_isolation` riêng, KHÔNG dùng lại
# `table inet shield` của block_ip — xem shield/security/isolation.py giải thích.
#
# Bất biến của khối này: `apply_isolation` chỉ trả True sau khi ĐỌC LẠI ruleset
# từ kernel và thấy đúng thứ mong đợi. Nếu áp xong mà verify không khớp, nó gỡ
# ngay và trả False — không bao giờ để lại luật rác nửa vời.


async def _isolation_snapshot() -> str:
    """Chụp `nft list ruleset` trước khi đổi. Điều tra sau sự cố cần biết
    firewall trông như thế nào TRƯỚC khi Shield chạm vào."""
    ok, out = await _run_capture(["nft", "list", "ruleset"])
    if not ok:
        return ""
    try:
        snap_dir = default_snapshot_dir()
        snap_dir.mkdir(parents=True, exist_ok=True)
        path = snap_dir / f"pre-isolation-{int(time.time())}.nft"
        path.write_text(out, encoding="utf-8")
        return str(path)
    except OSError as exc:
        logger.warning("Không lưu được snapshot trước cách ly: %s", exc)
        return ""


async def _isolation_table_json() -> str:
    """`nft -j list table inet shield_isolation`. Chuỗi rỗng nếu chưa có table."""
    ok, out = await _run_capture(
        ["nft", "-j", "list", "table", isolation.ISOLATION_FAMILY, isolation.ISOLATION_TABLE]
    )
    return out if ok else ""


async def apply_isolation(management_ip: str, preserve_dns: bool = False) -> tuple[bool, str]:
    try:
        ruleset = isolation.build_ruleset(management_ip, preserve_dns=preserve_dns)
    except ValueError as exc:
        return False, str(exc)

    snapshot = await _isolation_snapshot()

    # Áp lại khi đang cách ly phải cho ra đúng một trạng thái, không chồng luật.
    await release_isolation()

    proc = await asyncio.create_subprocess_exec(
        "nft", "-f", "-",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate(ruleset.encode())
    if proc.returncode != 0:
        err = stderr.decode(errors="ignore").strip()
        logger.error("apply_isolation: nft từ chối ruleset: %s", err)
        # Giao dịch nft là nguyên tử nên gần như chắc chắn không có gì vào được,
        # nhưng "gần như chắc chắn" không đủ cho một luật policy drop.
        await release_isolation()
        return False, f"nft từ chối ruleset: {err}"

    ok, reason = isolation.verify_isolation(
        await _isolation_table_json(), management_ip, preserve_dns=preserve_dns
    )
    if not ok:
        logger.error("apply_isolation: hậu điều kiện không khớp (%s) — gỡ ngay", reason)
        await release_isolation()
        return False, f"áp xong nhưng kiểm chứng thất bại: {reason}"

    logger.warning("ĐÃ CÁCH LY máy này; chỉ %s còn nối được. Snapshot: %s",
                   management_ip, snapshot or "(không lưu được)")
    return True, reason


async def release_isolation() -> tuple[bool, str]:
    """Gỡ cách ly. Idempotent: gỡ khi không có gì để gỡ vẫn là thành công.

    Idempotent là bắt buộc chứ không phải tiện tay: dead-man switch, người dùng
    bấm nút, và phục hồi sau crash đều có thể gọi hàm này cùng lúc cho cùng một
    lần cách ly. Nếu lần thứ hai trả về lỗi, caller sẽ tưởng máy vẫn đang bị
    cách ly và thử mãi.
    """
    ok, msg = await _run(["nft", "delete", "table",
                          isolation.ISOLATION_FAMILY, isolation.ISOLATION_TABLE])
    if ok:
        logger.warning("Đã gỡ cách ly endpoint (xoá table %s)", isolation.ISOLATION_TABLE)
        return True, "đã gỡ cách ly"
    # Xoá hỏng có hai lý do rất khác nhau: table không tồn tại (đã sạch) hoặc
    # nft thật sự lỗi (chưa sạch). Phải phân biệt, vì cái sau nghĩa là máy vẫn
    # đang nằm ngoài mạng.
    if not isolation.isolation_present(await _isolation_table_json()):
        return True, "không có cách ly nào đang áp"
    logger.error("release_isolation thất bại và table vẫn còn: %s", msg)
    return False, msg


async def isolation_state() -> tuple[bool, str]:
    """Máy này có đang bị cách ly không — đọc từ kernel, không từ trí nhớ agent."""
    present = isolation.isolation_present(await _isolation_table_json())
    return present, "đang cách ly" if present else "không cách ly"
