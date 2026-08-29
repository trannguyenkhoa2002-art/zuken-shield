"""Theo dõi 1 thiết bị nghi ngờ theo yêu cầu (KE-HOACH-SHIELD.md mục 2.5).

Không sniff toàn mạng liên tục — tốn CPU và đầy đĩa. Bật bằng lệnh
watch_device từ UI, tắt bằng unwatch_device. Mỗi phiên theo dõi làm 3 việc
song song:

1. `tcpdump -w ... -C 50 -W 4` — ghi bằng chứng, xoay vòng 4 file x 50MB
   (giới hạn cứng dung lượng, xem mục 6 rủi ro "Đĩa đầy vì pcap"). File pcap
   là bằng chứng có giá trị nhất nếu sau này cần điều tra/báo cáo, mở được
   trực tiếp bằng Wireshark thật để soi sâu hơn nếu cần.
2. Đếm bytes/giây: cần shield-packet-collector (tuỳ chọn); không có thì
   đồ thị đứng yên và giao diện nói rõ
   realtime.
3. Thống kê giao thức bằng `tshark` — dùng chính engine bóc tách giao thức
   của Wireshark (epan) thay vì tự đoán qua cổng TCP/UDP, nên nhận diện
   đúng cả traffic không dùng cổng chuẩn. Tuỳ chọn (gói `tshark` chỉ nằm ở
   Recommends, không phải Depends cứng — xem packaging/debian/control):
   thiếu thì bỏ qua bước này, 2 việc trên vẫn chạy bình thường.

Cả (2) và (3) đều broadcast trực tiếp qua IPC, KHÔNG đi qua Event bus/SQLite
vì đây là telemetry tần suất cao, ghi vào bảng events sẽ làm phình DB vô ích
(khác bản chất với Event của detector, nơi mỗi dòng có thể là bằng chứng cần
giữ).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from pathlib import Path

from shield.agent.ipc import IpcServer

logger = logging.getLogger("shield.traffic")

# Nhãn giao thức ưu tiên hiện cho người dùng khi 1 gói khớp nhiều lớp (ví dụ
# "eth:ethertype:ip:tcp:tls:http2" khớp cả tls lẫn http2) — chọn lớp ỨNG DỤNG
# cụ thể nhất thay vì lớp vận chuyển chung chung. Duyệt theo thứ tự này, khớp
# cái nào trước dùng cái đó; không khớp gì thì rơi về "tcp"/"udp"/"icmp" thô.
_PROTOCOL_PRIORITY = [
    "dns", "http2", "http", "tls", "ssh", "quic", "dhcp", "ntp", "mdns",
    "ssdp", "ftp", "smtp", "ftp-data", "nbns", "stun",
]


def _pick_protocol_label(frame_protocols: str) -> str:
    """`frame_protocols` là chuỗi tshark trả về kiểu
    "eth:ethertype:ip:tcp:tls:http2" — chọn 1 nhãn đại diện dễ hiểu."""
    if not frame_protocols:
        return "other"
    layers = frame_protocols.lower().split(":")
    for name in _PROTOCOL_PRIORITY:
        if name in layers:
            return name
    for name in ("tcp", "udp", "icmp", "arp"):
        if name in layers:
            return name
    return layers[-1] if layers else "other"


def default_pcap_dir() -> Path:
    env = os.environ.get("SHIELD_PCAP_DIR")
    if env:
        return Path(env)

    prod_candidate = Path("/var/lib/shield/pcaps")
    if prod_candidate.parent.exists() and os.access(prod_candidate.parent, os.W_OK):
        return prod_candidate

    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return data_home / "shield" / "pcaps"


class WatchSession:
    """1 phiên theo dõi cho 1 IP: tcpdump process + bộ đếm bytes/giây + thống
    kê giao thức qua tshark."""

    def __init__(self, ipc: IpcServer, ip: str, interface: str | None, mac: str | None = None) -> None:
        self.ipc = ipc
        self.ip = ip
        self.mac = mac
        self.interface = interface
        self.pcap_path: Path | None = None
        self._tcpdump_proc: asyncio.subprocess.Process | None = None
        self._counter_task: asyncio.Task | None = None
        self._sniffer = None
        self._byte_count = 0
        self._lock = asyncio.Lock()
        self._tshark_proc: asyncio.subprocess.Process | None = None
        self._protocol_task: asyncio.Task | None = None

    async def start(self) -> None:
        await self._start_tcpdump()
        self._counter_task = asyncio.create_task(self._run_byte_counter())
        if shutil.which("tshark"):
            self._protocol_task = asyncio.create_task(self._run_protocol_stats())
        else:
            logger.info("Không có 'tshark' — bỏ qua thống kê giao thức cho %s (cài gói tshark để bật)", self.ip)
        logger.info("Bắt đầu theo dõi %s (pcap: %s)", self.ip, self.pcap_path)

    async def _start_tcpdump(self) -> None:
        pcap_dir = default_pcap_dir()
        pcap_dir.mkdir(parents=True, exist_ok=True)
        subject = (self.mac or self.ip).replace(":", "")
        self.pcap_path = pcap_dir / f"{subject}-{int(time.time())}.pcap"

        cmd = ["tcpdump", "-n", "host", self.ip, "-w", str(self.pcap_path), "-C", "50", "-W", "4"]
        if self.interface:
            cmd[1:1] = ["-i", self.interface]
        try:
            self._tcpdump_proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            logger.error("Không tìm thấy 'tcpdump' trong PATH — không ghi được pcap bằng chứng.")
            self._tcpdump_proc = None
            return

        # tcpdump thoát ngay (thường do thiếu quyền CAP_NET_RAW) — không đợi
        # vô hạn, chỉ liếc nhanh để log lỗi rõ ràng thay vì im lặng thất bại.
        await asyncio.sleep(0.3)
        if self._tcpdump_proc.returncode is not None:
            stderr = await self._tcpdump_proc.stderr.read()
            logger.error(
                "tcpdump thoát ngay (mã %s) — không ghi được pcap: %s",
                self._tcpdump_proc.returncode,
                stderr.decode(errors="ignore").strip(),
            )
            self._tcpdump_proc = None

    async def _run_byte_counter(self) -> None:
        """Đồ thị bytes/giây — CẦN thành phần bắt gói tuỳ chọn.

        Bộ đếm cũ dùng scapy `AsyncSniffer`, và scapy đã rời khỏi lõi cùng ba
        collector kia (xem `packet_ingest.py`). Ghi pcap vẫn chạy bằng
        `tcpdump` và thống kê giao thức vẫn chạy bằng `tshark` — cả hai là
        chương trình RIÊNG, gọi qua subprocess, nên chúng không kéo thư viện
        nào vào tiến trình này.

        Không có bộ đếm thì đồ thị đứng ở 0 và giao diện nói rõ vì sao. Đó là
        mất một biểu đồ, không phải mất khả năng ghi bằng chứng.
        """
        logger.info(
            "Bộ đếm bytes/giây cho %s cần shield-packet-collector — bỏ qua.",
            self.ip)
        return

    async def _run_protocol_stats(self) -> None:
        """Đếm số gói theo giao thức mỗi giây bằng `tshark -T fields -e
        frame.protocols` — dùng đúng engine bóc tách giao thức của Wireshark
        (epan) nên nhận diện được cả traffic chạy sai cổng chuẩn, khác với
        đoán qua cổng TCP/UDP như cách làm đơn giản. Capture filter `-f`
        (BPF, lọc ở kernel) chứ không phải display filter, nên chi phí gần
        tương đương tcpdump/scapy ở trên, không phải chạy 2 lần capture
        nặng."""
        cmd = ["tshark", "-l", "-n", "-Q"]
        cmd += ["-i", self.interface or "any"]
        cmd += ["-f", f"host {self.ip}", "-T", "fields", "-e", "frame.protocols"]
        try:
            self._tshark_proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
        except FileNotFoundError:
            logger.error("Không chạy được 'tshark' dù đã tìm thấy trong PATH — bỏ qua thống kê giao thức")
            return

        counts: dict[str, int] = {}
        lock = asyncio.Lock()

        async def _read_lines() -> None:
            assert self._tshark_proc is not None and self._tshark_proc.stdout is not None
            async for raw_line in self._tshark_proc.stdout:
                line = raw_line.decode(errors="ignore").strip()
                if not line:
                    continue
                label = _pick_protocol_label(line)
                async with lock:
                    counts[label] = counts.get(label, 0) + 1

        reader_task = asyncio.create_task(_read_lines())
        try:
            while True:
                await asyncio.sleep(1)
                async with lock:
                    snapshot = dict(counts)
                    counts.clear()
                if snapshot:
                    await self.ipc.broadcast(
                        "traffic_protocols", {"ip": self.ip, "mac": self.mac, "counts": snapshot}
                    )
        finally:
            reader_task.cancel()

    async def stop(self) -> None:
        if self._counter_task is not None:
            self._counter_task.cancel()
        if self._protocol_task is not None:
            self._protocol_task.cancel()
        if self._sniffer is not None:
            self._sniffer.stop()
        if self._tcpdump_proc is not None and self._tcpdump_proc.returncode is None:
            self._tcpdump_proc.terminate()
            await self._tcpdump_proc.wait()
        if self._tshark_proc is not None and self._tshark_proc.returncode is None:
            self._tshark_proc.terminate()
            await self._tshark_proc.wait()
        logger.info("Đã dừng theo dõi %s", self.ip)


class TrafficManager:
    """Quản lý nhiều WatchSession — lệnh watch_device/unwatch_device gọi vào đây."""

    def __init__(self, ipc: IpcServer, interface: str | None = None) -> None:
        self.ipc = ipc
        self.interface = interface
        self._sessions: dict[str, WatchSession] = {}

    async def watch(self, ip: str, mac: str | None = None) -> bool:
        if ip in self._sessions:
            logger.info("%s đã được theo dõi từ trước", ip)
            return False
        session = WatchSession(self.ipc, ip, self.interface, mac)
        await session.start()
        self._sessions[ip] = session
        return True

    async def unwatch(self, ip: str) -> bool:
        session = self._sessions.pop(ip, None)
        if session is None:
            return False
        await session.stop()
        return True

    async def stop_all(self) -> None:
        for ip in list(self._sessions):
            await self.unwatch(ip)
