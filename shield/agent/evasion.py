"""Né tránh khẩn cấp — tự đổi MAC + xin IP mới liên tục trên interface của
CHÍNH máy này, để câu giờ khi nghi ngờ đang bị nhắm tới trực tiếp (ai đó
đang cố định vị/ tấn công đúng máy bạn qua MAC/IP cũ) trong lúc tìm giải
pháp lâu dài. Đây KHÔNG phải hành vi tấn công/che giấu khỏi pháp luật — chỉ
là tự thay đổi cấu hình mạng của chính thiết bị mình, tương đương bấm
"Forget network rồi kết nối lại" liên tục, việc user vẫn tự làm tay được.

Cách hoạt động: đổi `cloned-mac-address` của connection NetworkManager đang
active trên interface, rồi `nmcli connection up` để áp dụng — NM tự ngắt và
kết nối lại, DHCP server cấp lại IP cho MAC "mới", nên cả MAC lẫn IP đều đổi
trong 1 bước. Cố tình đi qua NetworkManager thay vì tự `ip link`/`dhclient`
thẳng: nếu sửa tay bằng `ip link`, NetworkManager (đang quản lý interface đó)
sẽ phát hiện lệch cấu hình và tự đặt lại theo ý nó ngay sau đó — không việc
gì cả.

Rủi ro đã biết, không né tránh: mọi kết nối mạng đang mở (SSH, video call,
tải file...) đều bị rớt mỗi lần đổi, vì địa chỉ IP nguồn thay đổi giữa
chừng. Đây là lý do tính năng này BẮT BUỘC người dùng tự bấm bật, kèm hộp
thoại xác nhận nêu rõ hậu quả — không có đường tự động bật.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re

logger = logging.getLogger("shield.evasion")

_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")


def random_mac() -> str:
    """Sinh 1 MAC ngẫu nhiên hợp lệ để làm cloned MAC.

    Byte đầu tiên: bit 0 (unicast, không phải multicast) phải là 0, bit 1
    (locally administered) phải là 1 — theo chuẩn IEEE 802, đây là cách khai
    báo "MAC này không phải MAC vendor thật, đã tự đặt" — không trùng dải MAC
    thật của bất kỳ hãng nào nên không giả mạo thiết bị của ai khác.
    """
    first_byte = random.randint(0, 255) & 0b11111110 | 0b00000010
    rest = [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first_byte, *rest])


async def _run(cmd: list[str], timeout: float = 15.0) -> tuple[bool, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except FileNotFoundError:
        return False, "Thiếu lệnh nmcli — cần NetworkManager để dùng tính năng này"
    except asyncio.TimeoutError:
        return False, f"Quá thời gian chờ ({timeout}s)"
    if proc.returncode != 0:
        return False, stderr.decode(errors="ignore").strip() or stdout.decode(errors="ignore").strip()
    return True, stdout.decode(errors="ignore")


async def active_connection_name(iface: str) -> str | None:
    """Tên connection NetworkManager đang active trên `iface`, hoặc None nếu
    interface không do NM quản lý (VD cấu hình tay bằng netplan/systemd-networkd
    — trường hợp đó tính năng này không hoạt động được, báo lỗi rõ ràng)."""
    ok, out = await _run(["nmcli", "-t", "-f", "DEVICE,CONNECTION", "device", "status"])
    if not ok:
        return None
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[0] == iface and parts[1] not in ("", "--"):
            return parts[1]
    return None


async def current_mac(iface: str) -> str | None:
    ok, out = await _run(["ip", "-o", "link", "show", "dev", iface])
    if not ok:
        return None
    m = re.search(r"link/ether ([0-9a-fA-F:]{17})", out)
    return m.group(1).lower() if m else None


async def current_ip(iface: str) -> str | None:
    ok, out = await _run(["ip", "-4", "-o", "addr", "show", "dev", iface])
    if not ok:
        return None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", out)
    return m.group(1) if m else None


async def rotate_identity(iface: str) -> tuple[bool, str, dict]:
    """Đổi MAC ngẫu nhiên + xin IP mới cho `iface`. Trả (ok, message, info)
    với info = {"mac": ..., "ip": ...} khi thành công."""
    if not _IFACE_RE.match(iface):
        return False, f"Interface không hợp lệ: {iface!r}", {}

    conn = await active_connection_name(iface)
    if not conn:
        return False, (
            f"Không tìm thấy connection NetworkManager nào đang active trên {iface} — "
            "interface này có thể không do NetworkManager quản lý."
        ), {}

    new_mac = random_mac()
    # Thử cả 2 tên thuộc tính (wifi và ethernet) — không cần biết trước loại
    # interface, đặt sai loại chỉ trả lỗi "unknown property" vô hại, bỏ qua.
    applied = False
    for prop in ("802-11-wireless.cloned-mac-address", "802-3-ethernet.cloned-mac-address"):
        ok, _ = await _run(["nmcli", "connection", "modify", conn, prop, new_mac])
        if ok:
            applied = True
    if not applied:
        return False, f"Không đặt được cloned MAC cho connection {conn!r}", {}

    ok, msg = await _run(["nmcli", "connection", "up", conn], timeout=30.0)
    if not ok:
        return False, f"Áp dụng MAC/IP mới thất bại: {msg}", {}

    mac = await current_mac(iface)
    ip = await current_ip(iface)
    logger.info("evasion: đã xoay danh tính %s -> MAC %s, IP %s", iface, mac, ip)
    return True, "OK", {"mac": mac, "ip": ip}


async def restore_identity(iface: str) -> tuple[bool, str]:
    """Trả interface về MAC phần cứng gốc — gọi khi TẮT tính năng, để máy
    không kẹt mãi ở 1 MAC ngẫu nhiên sau khi người dùng đã tắt né tránh."""
    if not _IFACE_RE.match(iface):
        return False, f"Interface không hợp lệ: {iface!r}"

    conn = await active_connection_name(iface)
    if not conn:
        return False, f"Không tìm thấy connection đang active trên {iface}"

    for prop in ("802-11-wireless.cloned-mac-address", "802-3-ethernet.cloned-mac-address"):
        await _run(["nmcli", "connection", "modify", conn, prop, "permanent"])

    ok, msg = await _run(["nmcli", "connection", "up", conn], timeout=30.0)
    if not ok:
        return False, f"Khôi phục MAC gốc thất bại: {msg}"
    logger.info("evasion: đã khôi phục MAC gốc cho %s", iface)
    return True, "OK"
