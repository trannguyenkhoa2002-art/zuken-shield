"""Low-overhead Linux endpoint telemetry using /proc and /sys snapshots."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket
import struct
import subprocess
from pathlib import Path

from shield.agent.bus import Bus
from shield.common.secrets import redact_text
from shield.common.models import Event, now

logger = logging.getLogger("shield.endpoint")
MAX_ITEMS = 20_000


def _decode_proc_address(value: str, ipv6: bool = False) -> tuple[str, int]:
    address, port_hex = value.split(":")
    raw = bytes.fromhex(address)
    if ipv6:
        # procfs stores each 32-bit IPv6 word in host byte order.
        raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        ip = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        ip = socket.inet_ntoa(struct.pack("<I", int(address, 16)))
    return ip, int(port_hex, 16)


# Dải cổng tạm thời của kernel. Đọc một lần, dùng để GHI NHẬN chứ không để
# lọc: "cổng này nằm trong dải tạm thời" là một quan sát; "vậy nó không phải
# server" là một suy đoán, và Shield không suy đoán thay người điều tra.
def _ephemeral_range(proc_root: Path = Path("/proc")) -> tuple[int, int]:
    try:
        low, high = (proc_root / "sys/net/ipv4/ip_local_port_range").read_text().split()
        return int(low), int(high)
    except (OSError, ValueError):
        return 32768, 60999


def _is_unbound_peer(rem_address: str) -> bool:
    """Socket này CHƯA nối tới đâu cả (địa chỉ + cổng đối tác đều bằng 0)."""
    try:
        host, port = rem_address.split(":")
    except ValueError:
        return False
    return int(port, 16) == 0 and int(host, 16) == 0


def network_snapshot(proc_net: Path = Path("/proc/net")) -> dict[str, dict]:
    """Socket đang chờ kết nối, TCP và UDP. Không lưu từng luồng client.

    TCP có trạng thái `LISTEN` (`st=0A`) nên câu hỏi "đây có phải server không"
    có câu trả lời dứt khoát từ kernel.

    **UDP thì KHÔNG.** Giao thức này không có trạng thái nghe. Thứ duy nhất
    phân biệt được ở procfs là socket đã `connect()` hay chưa: đã nối thì
    `st=01` và địa chỉ đối tác khác 0; chưa nối thì `st=07` và đối tác bằng 0.
    Đó cũng chính là tiêu chí `ss -lnu` dùng — đối chiếu trên máy thật: 17 socket
    `st=07` khớp đúng 17 dòng `ss -lnu`, và 3 socket `st=01` bị cả hai loại ra.

    Giới hạn phải nói ra: một socket chưa nối chỉ dùng để `sendto()` đi ra
    ngoài KHÔNG phân biệt được với một server socket. `ss -lnu` cũng vậy. Nên
    ở đây ghi `ephemeral_port` như một QUAN SÁT để người điều tra tự đánh giá,
    và KHÔNG lọc theo nó — lọc theo dải cổng là đoán, và đoán sai theo hướng
    im lặng là kiểu hỏng tệ nhất.
    """
    out: dict[str, dict] = {}
    low, high = _ephemeral_range()
    for filename, ipv6, udp in (("tcp", False, False), ("tcp6", True, False),
                                ("udp", False, True), ("udp6", True, True)):
        try:
            lines = (proc_net / filename).read_text().splitlines()[1:]
        except (FileNotFoundError, PermissionError, OSError):
            continue
        for line in lines[:MAX_ITEMS]:
            fields = line.split()
            if len(fields) < 10:
                continue
            if udp:
                # UDP_CLOSE (07) + chưa có đối tác. KHÔNG chép trạng thái 0A
                # của TCP sang đây: UDP không bao giờ mang trạng thái đó, và
                # một bản chép như vậy sẽ im lặng không thấy gì.
                if fields[3] != "07" or not _is_unbound_peer(fields[2]):
                    continue
            elif fields[3] != "0A":  # TCP_LISTEN
                continue
            try:
                ip, port = _decode_proc_address(fields[1], ipv6)
            except (ValueError, OSError):
                continue
            proto = f"{'udp' if udp else 'tcp'}{'6' if ipv6 else '4'}"
            item = {"protocol": proto, "ip": ip, "port": port, "inode": fields[9]}
            if udp:
                # Khoá gồm cả inode. Với UDP, HAI socket khác nhau có thể cùng
                # địa chỉ và cổng — đo được trên máy này: hai lần tham gia
                # multicast 239.255.255.250:3702 với hai inode khác nhau. Khoá
                # không có inode sẽ gộp chúng làm một và mất một socket.
                #
                # TCP giữ khoá cũ: hai listener cùng ip:port cần `SO_REUSEPORT`
                # và chưa gặp trên máy nào; đổi khoá TCP bây giờ sẽ làm 22
                # listener hiện có trông như đóng rồi mở lại một lượt.
                item["udp_state"] = "unconnected"
                item["ephemeral_port"] = low <= port <= high
                key = f"{proto}:{ip}:{port}:{fields[9]}"
            else:
                key = f"{proto}:{ip}:{port}"
            out[key] = item
    return out


# Trạng thái phân giải chủ sở hữu một socket lắng nghe. Bốn giá trị này là
# BỐN SỰ THẬT KHÁC NHAU và không được gộp: "không tìm ra" khác "không được
# phép nhìn", và "nhiều tiến trình cùng giữ" khác "một tiến trình".
RESOLVED = "resolved"
AMBIGUOUS = "ambiguous"
UNRESOLVED = "unresolved"
DENIED = "denied"


def socket_inode_owners(inodes, proc_root: Path = Path("/proc")) -> dict[str, dict]:
    """inode của socket -> tiến trình nào đang giữ nó.

    Trả về, cho mỗi inode được hỏi:

        {"owners": [{"pid": n, "start_ticks": "t"}, ...],   # đã sắp theo pid
         "observed_pids": [n, ...],
         "resolution": resolved | ambiguous | unresolved | denied}

    Vì sao `owners` chứ không phải một `pid`:

    - PID một mình KHÔNG phải danh tính. Linux dùng lại số PID, nên
      `resolver._process_key` từ chối dựng thực thể nếu thiếu `start_ticks`.
      Đọc `start_ticks` NGAY sau khi tìm ra pid là chỗ duy nhất cặp đó còn
      chắc chắn thuộc về nhau.
    - Một socket lắng nghe có thể do NHIỀU tiến trình giữ: fork kế thừa fd,
      hoặc `SO_REUSEPORT`. Bốc một cái làm "chủ sở hữu" là bịa. Ghi cả danh
      sách, đã sắp xếp, và nói rõ là mơ hồ.

    `observed_pids` là những pid thật sự thấy giữ inode, kể cả khi không đọc
    được `start_ticks` của chúng. Đó là quan sát được, không phải suy đoán —
    giữ lại để người điều tra biết "đã thấy pid này nhưng không xác nhận được
    danh tính", còn đồ thị thì KHÔNG dựng cạnh từ nó.

    MỘT lượt quét giải cho TẤT CẢ inode được hỏi. Đo trên máy thật: 421 tiến
    trình, 3.059 fd, 26 ms một lượt. Quét một lượt cho mỗi inode sẽ nhân con
    số đó lên số cổng vừa mở.
    """
    wanted = {str(inode) for inode in inodes if str(inode) not in ("", "0")}
    if not wanted:
        return {}
    targets = {f"socket:[{inode}]": inode for inode in wanted}
    found: dict[str, set[int]] = {inode: set() for inode in wanted}
    denied = 0

    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        try:
            names = os.listdir(fd_dir)
        except PermissionError:
            # Không được phép nhìn KHÁC với không có gì để thấy. Đếm lại để
            # nói đúng ở `resolution`.
            denied += 1
            continue
        except OSError:
            continue
        pid = int(entry.name)
        for name in names:
            try:
                link = os.readlink(fd_dir / name)
            except OSError:
                continue
            inode = targets.get(link)
            if inode is not None:
                found[inode].add(pid)

    out: dict[str, dict] = {}
    for inode, pids in found.items():
        owners = []
        for pid in sorted(pids):
            ticks = _start_ticks(proc_root, pid)
            if not ticks:
                # Tiến trình đã thoát giữa hai bước. Để trống, KHÔNG đoán:
                # một danh tính bịa ra sẽ gộp tiến trình này với mọi tiến
                # trình từng mang số PID đó.
                continue
            owners.append({"pid": pid, "start_ticks": ticks})
        if owners:
            resolution = RESOLVED if len(owners) == 1 else AMBIGUOUS
        elif denied and not pids:
            resolution = DENIED
        else:
            resolution = UNRESOLVED
        out[inode] = {"owners": owners, "observed_pids": sorted(pids),
                      "resolution": resolution}
    return out


def service_snapshot() -> dict[str, dict]:
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return {}
    out: dict[str, dict] = {}
    for line in result.stdout.splitlines()[:MAX_ITEMS]:
        fields = line.split(None, 4)
        if len(fields) < 4 or not fields[0].endswith(".service"):
            continue
        unit, load, active, sub = fields[:4]
        out[unit] = {"unit": unit, "load": load, "active": active, "sub": sub}
    return out


def _start_ticks(proc_root: Path, pid: int) -> str:
    """`start_ticks` của một PID. Rỗng nếu không đọc được — KHÔNG đoán.

    Dùng cho tiến trình CHA: `resolver._process_key` từ chối dựng thực thể khi
    thiếu mốc này, vì Linux dùng lại số PID và gộp nhầm hai tiến trình cha là
    cách để cây tiến trình nói dối một cách thuyết phục.
    """
    try:
        stat = (proc_root / str(pid) / "stat").read_text(errors="replace")
        return stat[stat.rfind(")") + 2:].split()[19]
    except (OSError, ValueError, IndexError):
        return ""


def process_snapshot(proc_root: Path = Path("/proc")) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit() or len(out) >= MAX_ITEMS:
            continue
        try:
            pid = int(entry.name)
            stat = (entry / "stat").read_text(errors="replace")
            end = stat.rfind(")")
            # `comm` nằm trong ngoặc và CÓ THỂ chứa cả ngoặc lẫn khoảng trắng
            # ("(sd-pam)", "(Web Content)"), nên phải cắt theo dấu đóng ngoặc
            # CUỐI CÙNG chứ không tách theo khoảng trắng.
            comm = stat[stat.find("(") + 1:end] if end > 0 else ""
            fields = stat[end + 2:].split()
            ppid = int(fields[1])
            start_ticks = fields[19]
            exe = os.readlink(entry / "exe")
            raw_cmd = (entry / "cmdline").read_bytes()[:4096]
            cmdline = raw_cmd.replace(b"\0", b" ").decode(errors="replace").strip()
            # Dòng lệnh là chỗ mật khẩu và khoá API hay nằm nhất (`--password=`,
            # `API_KEY=`, token trên URL) và nó được LƯU vào bảng events rồi
            # xuất ra file log. Che bằng bộ luật CHUNG — không phải bộ luật
            # riêng của file này.
            cmdline = redact_text(cmdline)
            # `uid` lấy từ chủ sở hữu thư mục `/proc/<pid>` — một lần `stat()`,
            # rẻ hơn đọc và bóc `/proc/<pid>/status`.
            #
            # Trước đây ảnh chụp này KHÔNG có uid, ppid hay comm, trong khi
            # nguồn eBPF cho cùng một sự việc thì có cả ba. Hai nguồn mô tả
            # cùng một tiến trình bằng hai tập trường khác nhau nghĩa là mọi
            # thứ đọc chúng phải biết event đến từ đâu — và sớm muộn sẽ có chỗ
            # quên.
            out[pid] = {
                "pid": pid, "ppid": ppid, "uid": entry.stat().st_uid,
                "comm": comm[:256], "start_ticks": start_ticks,
                "exe": exe, "cmdline": cmdline,
                "parent_start_ticks": _start_ticks(proc_root, ppid),
            }
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError, OSError):
            continue
    return out


def usb_snapshot(sys_root: Path = Path("/sys/bus/usb/devices")) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not sys_root.exists():
        return out
    for entry in sys_root.iterdir():
        try:
            vendor = (entry / "idVendor").read_text().strip()
            product = (entry / "idProduct").read_text().strip()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        def optional(name: str, entry: Path = entry) -> str:
            try:
                return (entry / name).read_text(errors="replace").strip()[:256]
            except (FileNotFoundError, PermissionError, OSError):
                return ""
        out[entry.name] = {
            "device": entry.name, "vendor_id": vendor, "product_id": product,
            "manufacturer": optional("manufacturer"), "product": optional("product"),
            "serial": optional("serial"),
        }
    return out


def _hash_file(path: Path, max_bytes: int = 64 * 1024 * 1024) -> dict:
    stat = path.stat()
    if not path.is_file():
        return {"kind": "other", "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    digest = hashlib.sha256()
    read = 0
    with path.open("rb") as handle:
        while read < max_bytes:
            chunk = handle.read(min(1024 * 1024, max_bytes - read))
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
    return {
        "kind": "file", "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
        "sha256": digest.hexdigest(), "hash_complete": read == stat.st_size,
    }


def fim_snapshot(paths: list[Path], max_files: int = 5000) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for root in paths:
        candidates = [root] if root.is_file() else root.rglob("*") if root.is_dir() else []
        for path in candidates:
            if len(out) >= max_files:
                return out
            try:
                if path.is_symlink():
                    continue
                out[str(path)] = {"path": str(path), **_hash_file(path)}
            except (FileNotFoundError, PermissionError, OSError):
                continue
    return out


def snapshot_changes(old: dict, new: dict) -> tuple[list, list, list]:
    added = [new[key] for key in new.keys() - old.keys()]
    removed = [old[key] for key in old.keys() - new.keys()]
    changed = [{"before": old[key], "after": new[key]} for key in old.keys() & new.keys() if old[key] != new[key]]
    return added, removed, changed


async def emit_bootstrap_listeners(event_bus: Bus, network: dict) -> int:
    """Nói ra những cổng ĐÃ mở trước khi Shield bắt đầu nhìn.

    Ảnh chụp đầu tiên của `endpoint_loop` chỉ dùng làm mốc so sánh, nên 39
    socket đang mở trên máy này (22 TCP + 17 UDP) chưa bao giờ sinh ra một
    event nào và không bao giờ vào đồ thị. Trên một máy khởi động dịch vụ
    trước Shield, đó là phần lớn bề mặt mạng.

    Nhưng KHÔNG được phát chúng dưới dạng `listener_opened`. Loại event đó
    mang nghĩa "cổng này vừa mở", và nghĩa đó đi vào ba nơi: detector cảnh báo
    cổng nhạy cảm, baseline hành vi, và mốc thời gian của cạnh trong đồ thị.
    Dùng lại nó ở đây là bịa ra một thời điểm mở — mỗi lần khởi động lại agent
    sẽ thành một loạt "cổng vừa mở" cho những cổng đã mở từ hôm qua.

    `listener_observed` nói đúng thứ Shield biết: *cổng này đang tồn tại lúc
    tôi bắt đầu nhìn, và tôi KHÔNG biết nó mở từ bao giờ.* Vì thế event này
    không có `opened_at`, và sẽ không bao giờ có.

    Phát lại ở MỖI lần khởi động là có chủ ý: đó là một quan sát mới có thật,
    đồ thị đã hợp nhất theo khoá nên không nhân bản, và một cờ `bootstrap_done`
    bền vững sẽ là một kho trạng thái nữa để lệch.
    """
    if not network:
        return 0
    started = now()
    owners = await asyncio.to_thread(
        socket_inode_owners, [item.get("inode") for item in network.values()])
    for item in network.values():
        payload = dict(item)
        payload.update(owners.get(str(item.get("inode", "")), {}))
        payload.update({"bootstrap": True, "observed_at": started,
                        "agent_started_ts": started})
        await event_bus.publish(Event(started, "endpoint", "listener_observed", payload))
    return len(network)


async def endpoint_loop(event_bus: Bus, interval_s: float = 5.0) -> None:
    processes = await asyncio.to_thread(process_snapshot)
    usb = await asyncio.to_thread(usb_snapshot)
    network = await asyncio.to_thread(network_snapshot)
    services = await asyncio.to_thread(service_snapshot)
    # Một lượt quét `/proc/*/fd` chung cho TẤT CẢ socket — đo được 24 ms cho 39
    # socket. Quét một lượt cho mỗi socket sẽ là 20 lần con số đó.
    await emit_bootstrap_listeners(event_bus, network)
    cycle = 0
    while True:
        await asyncio.sleep(max(1.0, interval_s))
        try:
            next_processes, next_usb, next_network = await asyncio.gather(
                asyncio.to_thread(process_snapshot), asyncio.to_thread(usb_snapshot),
                asyncio.to_thread(network_snapshot),
            )
            added, removed, changed = snapshot_changes(processes, next_processes)
            # PID reuse between polls is a process exit followed by a start.
            removed.extend(change["before"] for change in changed)
            added.extend(change["after"] for change in changed)
            for item in added:
                await event_bus.publish(Event(now(), "endpoint", "process_started", item))
            for item in removed:
                await event_bus.publish(Event(now(), "endpoint", "process_exited", item))
            added, removed, _ = snapshot_changes(usb, next_usb)
            for item in added:
                await event_bus.publish(Event(now(), "endpoint", "usb_added", item))
            for item in removed:
                await event_bus.publish(Event(now(), "endpoint", "usb_removed", item))
            added, removed, _ = snapshot_changes(network, next_network)
            # Phân giải chủ sở hữu CHỈ cho cổng vừa mở, và trong MỘT lượt quét
            # chung. Trên máy thật `listener_opened` phát ~0,2 lần mỗi giờ, nên
            # ở trạng thái bình thường vòng này không quét gì cả — khác hẳn
            # việc quét /proc/*/fd mỗi 5 giây.
            if added:
                owners = await asyncio.to_thread(
                    socket_inode_owners, [item.get("inode") for item in added])
                for item in added:
                    item.update(owners.get(str(item.get("inode", "")), {}))
            for item in added:
                await event_bus.publish(Event(now(), "endpoint", "listener_opened", item))
            for item in removed:
                await event_bus.publish(Event(now(), "endpoint", "listener_closed", item))
            cycle += 1
            if cycle % 12 == 0:  # 60s with the default process interval
                next_services = await asyncio.to_thread(service_snapshot)
                _, _, changed = snapshot_changes(services, next_services)
                for change in changed:
                    await event_bus.publish(Event(now(), "endpoint", "service_changed", change))
                services = next_services
            processes, usb, network = next_processes, next_usb, next_network
        except Exception:
            logger.exception("endpoint snapshot failed")


async def fim_loop(event_bus: Bus, paths: list[Path], interval_s: float = 30.0, store=None) -> None:
    current = await asyncio.to_thread(fim_snapshot, paths)
    persisted = store.load_fim_baseline() if store is not None else {}
    baseline = persisted or current
    if store is not None and not persisted:
        store.replace_fim_baseline(current)
    logger.info("FIM baseline: %d entries across %d configured paths", len(baseline), len(paths))
    while True:
        added, removed, changed = snapshot_changes(baseline, current)
        for kind, items in (("file_created", added), ("file_deleted", removed)):
            for item in items:
                await event_bus.publish(Event(now(), "fim", kind, item))
        for change in changed:
            await event_bus.publish(Event(now(), "fim", "file_modified", change))
        baseline = current
        if store is not None:
            store.replace_fim_baseline(current)
        await asyncio.sleep(max(5.0, interval_s))
        current = await asyncio.to_thread(fim_snapshot, paths)
