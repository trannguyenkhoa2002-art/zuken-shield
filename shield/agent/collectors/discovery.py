"""Collector phát hiện thiết bị — arp-scan mỗi 60s + nmap -sn mỗi 15 phút
(KE-HOACH-SHIELD.md mục 2.2). Chỉ mô tả sự thật, không quyết định nguy hiểm:
mỗi host thấy được đẩy ra Event(kind="host_seen"), detector mới có logic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time

from shield.agent.bus import Bus
from shield.agent import switch
from shield.common.models import Event, now

logger = logging.getLogger("shield.discovery")

ARP_SCAN_INTERVAL_S = 60
NMAP_INTERVAL_S = 15 * 60

_ARP_LINE_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$")
_NMAP_IP_RE = re.compile(r"Nmap scan report for (?:\S+ \()?([\d.]+)\)?")
_NMAP_MAC_RE = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17})(?: \((.*)\))?")


def detect_interface() -> str | None:
    """Dò interface đang có default route — dùng khi không cấu hình --interface."""
    try:
        out = subprocess_run(["ip", "route", "get", "1.1.1.1"])
        m = re.search(r"dev (\S+)", out)
        return m.group(1) if m else None
    except Exception:
        logger.exception("Không dò được interface mặc định")
        return None


def detect_subnet(interface: str) -> str | None:
    """CIDR subnet của interface, dùng làm target cho `nmap -sn`."""
    try:
        out = subprocess_run(["ip", "-4", "-o", "addr", "show", "dev", interface])
        m = re.search(r"inet (\S+)", out)
        if not m:
            return None
        iface = ipaddress.ip_interface(m.group(1))
        return str(iface.network)
    except Exception:
        logger.exception("Không dò được subnet cho interface %s", interface)
        return None


def detect_gateway_ip() -> str | None:
    """IP gateway hiện tại — dùng để gợi ý wizard baseline (mục 2.1)."""
    try:
        out = subprocess_run(["ip", "route", "show", "default"])
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except Exception:
        logger.exception("Không dò được gateway IP")
        return None


def detect_gateway_mac(gw_ip: str) -> str | None:
    """MAC gateway theo bảng ARP hiện tại của kernel — chỉ có nếu đã từng ping."""
    try:
        out = subprocess_run(["ip", "neigh", "show", gw_ip])
        m = re.search(r"lladdr ([0-9a-fA-F:]{17})", out)
        return m.group(1).lower() if m else None
    except Exception:
        logger.exception("Không dò được gateway MAC cho %s", gw_ip)
        return None


def subprocess_run(cmd: list[str]) -> str:
    import subprocess

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    return result.stdout


def _parse_arp_scan(output: str) -> list[dict]:
    hosts = []
    for line in output.splitlines():
        m = _ARP_LINE_RE.match(line)
        if not m:
            continue
        ip, mac, vendor = m.groups()
        hosts.append({"ip": ip, "mac": mac.lower(), "vendor_hint": vendor.strip() or None})
    return hosts


def _parse_nmap_sn(output: str) -> list[dict]:
    hosts = []
    current_ip: str | None = None
    for line in output.splitlines():
        m_ip = _NMAP_IP_RE.search(line)
        if m_ip:
            current_ip = m_ip.group(1)
            continue
        m_mac = _NMAP_MAC_RE.search(line)
        if m_mac and current_ip:
            mac, vendor = m_mac.groups()
            hosts.append({"ip": current_ip, "mac": mac.lower(), "vendor_hint": vendor})
            current_ip = None
    return hosts


async def run_arp_scan(interface: str | None) -> list[dict]:
    cmd = ["arp-scan", "--localnet", "--retry=2"]
    if interface:
        cmd += ["--interface", interface]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        logger.warning("arp-scan lỗi (%s): %s", proc.returncode, stderr.decode(errors="ignore")[:300])
        return []
    return _parse_arp_scan(stdout.decode(errors="ignore"))


async def run_nmap_sweep(interface: str | None) -> list[dict]:
    iface = interface or await asyncio.to_thread(detect_interface)
    if not iface:
        logger.warning("Không xác định được interface để quét nmap -sn")
        return []
    subnet = await asyncio.to_thread(detect_subnet, iface)
    if not subnet:
        logger.warning("Không xác định được subnet để quét nmap -sn")
        return []

    proc = await asyncio.create_subprocess_exec(
        "nmap", "-sn", subnet, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        logger.warning("nmap lỗi (%s): %s", proc.returncode, stderr.decode(errors="ignore")[:300])
        return []
    return _parse_nmap_sn(stdout.decode(errors="ignore"))


async def discovery_loop(event_bus: Bus, interface: str | None = None) -> None:
    """Chạy vô hạn: arp-scan mỗi ARP_SCAN_INTERVAL_S, chèn thêm nmap -sn định kỳ."""
    last_nmap = time.monotonic() - NMAP_INTERVAL_S
    while True:
        try:
            # Công tắc trong app (switch.py). arp-scan/nmap là thứ khiến NAC
            # và IDS của trường/cơ quan đánh dấu máy này đang quét mạng, nên
            # cổng chặn nằm ngay trước lần quét đầu tiên của mỗi vòng.
            if not switch.allows("active_scan"):
                await asyncio.sleep(ARP_SCAN_INTERVAL_S)
                continue
            hosts = await run_arp_scan(interface)
            for h in hosts:
                await event_bus.publish(
                    Event(ts=now(), source="discovery", kind="host_seen", data=h)
                )
            # INFO chứ không phải DEBUG: đây là bằng chứng quét THÀNH CÔNG
            # duy nhất trong log ở mức mặc định (không cần cờ -v) — thiếu nó,
            # quét ra 0 host và quét thành công đều im lặng như nhau, không
            # ai biết arp-scan có thực sự chạy hay không (KE-HOACH-SHIELD.md
            # mục "verify" — hành động phải để lại dấu vết kiểm chứng được).
            logger.info("arp-scan thấy %d host", len(hosts))
        except FileNotFoundError:
            logger.error("Không tìm thấy 'arp-scan' trong PATH. Chạy install.sh trước.")
        except Exception:
            logger.exception("Lỗi khi chạy arp-scan")

        # Đồng hồ ĐƠN ĐIỆU cho một khoảng chờ trong tiến trình.
        #
        # Máy này đã quan sát được đồng hồ tường nhảy lùi ~10 giờ lúc boot khi
        # NTP đồng bộ lần đầu. Với `time.time()`, một cú nhảy lùi như vậy làm
        # lượt quét nmap kế tiếp bị hoãn đúng bằng khoảng nhảy — im lặng, và
        # trông y hệt "mạng đang yên tĩnh". Mốc thời gian LƯU vào sự kiện vẫn là
        # đồng hồ tường; chỉ phép đo khoảng cách mới đổi.
        if time.monotonic() - last_nmap > NMAP_INTERVAL_S:
            last_nmap = time.monotonic()
            try:
                hosts = await run_nmap_sweep(interface)
                for h in hosts:
                    await event_bus.publish(
                        Event(ts=now(), source="discovery", kind="host_seen", data=h)
                    )
                logger.info("nmap -sn thấy %d host", len(hosts))
            except FileNotFoundError:
                logger.error("Không tìm thấy 'nmap' trong PATH. Chạy install.sh trước.")
            except Exception:
                logger.exception("Lỗi khi chạy nmap -sn")

        await asyncio.sleep(ARP_SCAN_INTERVAL_S)
