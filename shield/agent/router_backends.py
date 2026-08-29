"""Đọc lưu lượng theo từng thiết bị TỪ ROUTER — dùng cho kiểm thử mạng, xem
thiết bị nào đang dùng nhiều băng thông. Không sniff traffic của thiết bị
khác trên máy Shield (trên mạng switch thông thường máy bạn vốn không thấy
được traffic đó — xem thảo luận trong hội thoại).

Thiết kế theo backend có thể cắm/thay, KHÔNG fix cứng vào 1-2 hãng router:

- ssh_conntrack: SSH vào router chạy Linux (OpenWrt/DD-WRT/EdgeOS/GL.iNet,
  pfSense bản Linux...) và cộng dồn byte theo IP từ bảng conntrack của
  kernel (/proc/net/nf_conntrack) — file này tồn tại sẵn trên hầu hết router
  Linux có NAT bật, không cần cài thêm gói gì trên router.
- custom_script: chạy 1 script BẤT KỲ do bạn tự viết cho đúng router của
  mình (gọi API riêng của hãng, cào web admin, đọc SNMP OID riêng...).
  Script chỉ cần in JSON đúng schema ra stdout — đây là lối thoát cho router
  không hỗ trợ SSH/conntrack (đa số router ISP cấp/stock TP-Link, Xiaomi...).
  Nhờ vậy Shield không phải "biết" trước mọi hãng router, chỉ cần 1 script.

Mỗi backend trả (ok, message, hosts) với hosts là list[dict]:
    {"ip": str, "mac": str | None, "rx_bytes": int, "tx_bytes": int}
Số byte là CỘNG DỒN (cumulative) — agent tự tính delta giữa 2 lần poll để ra
tốc độ tức thời (xem router_traffic_loop ở agent/__main__.py).

Contract cho custom_script (in ra stdout, đúng schema, sai là bị bỏ qua):
    [{"ip": "192.168.1.23", "mac": "aa:bb:cc:dd:ee:ff",
      "rx_bytes": 10485760, "tx_bytes": 2097152}, ...]
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re

logger = logging.getLogger("shield.router_backends")

# Khớp 1 chiều "src=<ip> dst=<ip> sport=<n> dport=<n> [packets=<n>] bytes=<n>"
# trong 1 dòng /proc/net/nf_conntrack — mỗi kết nối có 2 chiều (original +
# reply), findall() trả về cả 2. Không quan tâm hướng nào là "gửi"/"nhận"
# theo NAT — chỉ cộng dồn theo IP xuất hiện ở vị trí src (tx) và dst (rx),
# đơn giản và đủ dùng để xếp hạng thiết bị nào dùng nhiều băng thông.
_CONNTRACK_TUPLE_RE = re.compile(
    r"src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=\d+\s+dport=\d+"
    r"(?:\s+packets=\d+)?\s+bytes=(\d+)"
)


def _parse_conntrack(text: str, lan_net: ipaddress.IPv4Network) -> list[dict]:
    tx: dict[str, int] = {}
    rx: dict[str, int] = {}
    for src, dst, nbytes in _CONNTRACK_TUPLE_RE.findall(text):
        n = int(nbytes)
        tx[src] = tx.get(src, 0) + n
        rx[dst] = rx.get(dst, 0) + n

    hosts = []
    for ip in set(tx) | set(rx):
        try:
            if ipaddress.ip_address(ip) not in lan_net:
                continue
        except ValueError:
            continue
        hosts.append({"ip": ip, "mac": None, "rx_bytes": rx.get(ip, 0), "tx_bytes": tx.get(ip, 0)})
    return hosts


async def ssh_conntrack_poll(
    host: str, user: str, port: int, key_path: str | None, lan_subnet: str
) -> tuple[bool, str, list[dict]]:
    """SSH vào router, đọc bảng conntrack, quy về danh sách thiết bị LAN.
    `lan_subnet` là CIDR mạng nhà (dò bằng detect_subnet() ở discovery.py) —
    dùng để lọc bỏ các IP WAN lẫn trong bảng conntrack."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-p", str(port)]
    if key_path:
        cmd += ["-i", key_path]
    cmd += [f"{user}@{host}", "cat /proc/net/nf_conntrack 2>/dev/null || cat /proc/net/ip_conntrack 2>/dev/null"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        return False, "Không tìm thấy lệnh 'ssh' trên máy này", []

    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode(errors="ignore").strip()
        logger.error("ssh_conntrack_poll %s thất bại: %s", host, err)
        return False, err or "SSH thất bại (kiểm tra key/quyền đăng nhập)", []

    try:
        lan_net = ipaddress.ip_network(lan_subnet, strict=False)
    except ValueError as e:
        return False, f"Subnet LAN không hợp lệ: {e}", []

    hosts = _parse_conntrack(stdout.decode(errors="ignore"), lan_net)
    logger.info("ssh_conntrack_poll %s: %d thiết bị", host, len(hosts))
    return True, "OK", hosts


async def custom_script_poll(path: str) -> tuple[bool, str, list[dict]]:
    """Chạy 1 script tuỳ chỉnh, kỳ vọng JSON list đúng schema ra stdout —
    xem docstring đầu file. Cho phép Shield hỗ trợ BẤT KỲ router nào mà
    không cần biết trước hãng/API của nó."""
    try:
        proc = await asyncio.create_subprocess_exec(
            path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except (FileNotFoundError, PermissionError) as e:
        return False, f"Không chạy được script: {e}", []

    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        return False, stderr.decode(errors="ignore").strip() or f"Script thoát mã {proc.returncode}", []

    try:
        data = json.loads(stdout.decode(errors="ignore"))
    except json.JSONDecodeError as e:
        return False, f"Script không in JSON hợp lệ ra stdout: {e}", []
    if not isinstance(data, list):
        return False, "Script phải in ra 1 JSON list (xem docstring router_backends.py)", []

    hosts = []
    for item in data:
        if not isinstance(item, dict) or "ip" not in item:
            continue
        try:
            hosts.append(
                {
                    "ip": str(item["ip"]),
                    "mac": item.get("mac"),
                    "rx_bytes": int(item.get("rx_bytes", 0)),
                    "tx_bytes": int(item.get("tx_bytes", 0)),
                }
            )
        except (TypeError, ValueError):
            continue
    logger.info("custom_script_poll %s: %d thiết bị", path, len(hosts))
    return True, "OK", hosts


async def poll(config: dict, lan_subnet: str | None) -> tuple[bool, str, list[dict]]:
    """Điểm vào duy nhất — agent chỉ gọi hàm này, không biết chi tiết backend.
    Thêm backend mới = thêm 1 nhánh ở đây, không đụng gì tới __main__.py."""
    kind = config.get("type")
    if kind == "ssh_conntrack":
        if not lan_subnet:
            return False, "Chưa xác định được subnet LAN của máy này", []
        return await ssh_conntrack_poll(
            host=str(config.get("host", "")),
            user=str(config.get("user", "root")),
            port=int(config.get("port", 22)),
            key_path=config.get("key_path") or None,
            lan_subnet=lan_subnet,
        )
    if kind == "custom_script":
        return await custom_script_poll(str(config.get("path", "")))
    if kind in (None, "disabled"):
        return True, "disabled", []
    return False, f"Loại backend không hỗ trợ: {kind!r}", []
