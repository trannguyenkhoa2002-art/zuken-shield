"""Telemetry nhân hệ điều hành qua eBPF, với fallback tường minh theo từng loại.

KE-HOACH-SHIELD-2.0.md mục 0.4.

Trước 2.0, file này chạy MỘT chương trình bpftrace phát duy nhất `process_exec`,
trong khi `KernelTelemetrySelector` khai năng lực `("process", "file", "socket",
...)` và `BehaviorChainDetector` chờ chuỗi `process_exec -> file_write ->
socket_connect`. Hai mắt xích sau không bao giờ tới. Chuỗi hành vi vì thế chưa
bao giờ kích hoạt từ dữ liệu thật — chỉ từ event tổng hợp trong test — nhưng UI
vẫn hiển thị nó như một khả năng đang hoạt động.

Nguyên tắc của file này: **năng lực được đo, không được khai.** Lúc khởi động,
từng đoạn chương trình được thử biên dịch và gắn thật vào kernel. Chỉ loại nào
gắn được mới được tính là có. Kết quả ghi vào collector health theo TỪNG loại
event, nên UI nói đúng cái đang có thay vì cái đáng lẽ phải có.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from shield.agent.collectors.ratelimit import RateLimiter
from shield.common.models import Event, now

logger = logging.getLogger("shield.kernel")

# Mỗi loại event có một danh sách phương án, ưu tiên giàu thông tin trước. Nếu
# phương án đầu không biên dịch được trên kernel này, thử phương án sau. Đây là
# "fallback rõ ràng khi kernel/backend không hỗ trợ": không có phương án nào
# chạy thì loại đó được ghi nhận là KHÔNG có, chứ không im lặng biến mất.
#
# Ký tự đầu mỗi dòng là nhãn loại, để một tiến trình bpftrace duy nhất phát
# nhiều loại mà phía đọc vẫn tách được.

_EXEC_PRIMARY = r'''tracepoint:syscalls:sys_enter_execve {
  printf("X\t%d\t%d\t%s\t%s\n", pid, uid, comm, str(args.filename));
}'''

# CỐ Ý dùng openat có cờ ghi, KHÔNG dùng sys_enter_write. `write()` bắn mỗi dòng
# log, mỗi lần in ra màn hình — hàng chục nghìn sự kiện mỗi giây trên một máy
# nhàn rỗi. Nó sẽ nhấn chìm bus và bỏ đói mọi collector khác, để đổi lấy tín
# hiệu gần như bằng không. Mở file để ghi là xấp xỉ rẻ và đúng ngữ nghĩa cho
# "tiến trình này tạo/sửa một file".
# O_WRONLY = 1, O_RDWR = 2.
_WRITE_PRIMARY = r'''tracepoint:syscalls:sys_enter_openat /(args.flags & 3) != 0/ {
  printf("W\t%d\t%d\t%s\t%s\n", pid, uid, comm, str(args.filename));
}'''

# Phương án đầu đọc sockaddr để lấy IP và cổng đích — bằng chứng có giá trị hơn
# hẳn. Nó cần định nghĩa struct từ BTF, thứ không phải kernel nào cũng có.
#
# BA phương án, thử theo thứ tự, và `probe_support()` ĐO chứ không suy đoán cái
# nào chạy được. Thứ tự này quan trọng: nếu gộp cả IPv6 vào một chương trình
# duy nhất thì một kernel thiếu BTF cho `sockaddr_in6` sẽ làm hỏng luôn cả
# nhánh IPv4 — mất một thứ đang chạy tốt để đổi lấy một thứ chưa chắc có.
#
# AF_INET = 2, AF_INET6 = 10, và hai họ dùng HAI thẻ khác nhau. IPv4 giữ thẻ
# `C` với `ntop()` — nó đúng và đã chạy từ 2.0. IPv6 dùng thẻ `6` và phát bốn
# TỪ 32 BIT thô, vì trên kernel này `ntop()` trả về `::` cho mọi địa chỉ IPv6:
# bpftrace đọc được vô hướng từ vùng nhớ người dùng nhưng đọc mảng thì ra 0.
# Xem `parse_line` để biết cách đo ra kết luận đó. Cả hai thẻ cùng cho ra
# `remote_ip`/`remote_port`, nên schema event không có trường mới.
_CONNECT_DUAL = r'''tracepoint:syscalls:sys_enter_connect {
  $sa = (struct sockaddr *)args.uservaddr;
  if ($sa->sa_family == 2) {
    $in = (struct sockaddr_in *)args.uservaddr;
    printf("C\t%d\t%d\t%s\t%s\t%d\n", pid, uid, comm,
           ntop($in->sin_addr.s_addr),
           (($in->sin_port >> 8) & 0xff) | (($in->sin_port & 0xff) << 8));
  }
  if ($sa->sa_family == 10) {
    $in6 = (struct sockaddr_in6 *)args.uservaddr;
    printf("6\t%d\t%d\t%s\t%08x\t%08x\t%08x\t%08x\t%d\n", pid, uid, comm,
           $in6->sin6_addr.in6_u.u6_addr32[0], $in6->sin6_addr.in6_u.u6_addr32[1],
           $in6->sin6_addr.in6_u.u6_addr32[2], $in6->sin6_addr.in6_u.u6_addr32[3],
           (($in6->sin6_port >> 8) & 0xff) | (($in6->sin6_port & 0xff) << 8));
  }
}'''

# Chỉ IPv4 — phương án đã chạy từ 2.0. Giữ nguyên làm lưới an toàn: nếu kernel
# này không đọc được `sockaddr_in6` thì vẫn thấy IPv4 y như trước.
_CONNECT_PRIMARY = r'''tracepoint:syscalls:sys_enter_connect {
  $sa = (struct sockaddr *)args.uservaddr;
  if ($sa->sa_family == 2) {
    $in = (struct sockaddr_in *)args.uservaddr;
    printf("C\t%d\t%d\t%s\t%s\t%d\n", pid, uid, comm,
           ntop($in->sin_addr.s_addr),
           (($in->sin_port >> 8) & 0xff) | (($in->sin_port & 0xff) << 8));
  }
}'''

# Phương án dự phòng: không có địa chỉ đích, nhưng vẫn biết tiến trình nào đã
# mở kết nối ra ngoài. Đủ để chuỗi hành vi hoạt động; kém hơn để điều tra. Chỗ
# nào dùng nó đều được ghi lại để không ai nhầm hai mức bằng chứng này.
_CONNECT_FALLBACK = r'''tracepoint:syscalls:sys_enter_connect {
  printf("C\t%d\t%d\t%s\n", pid, uid, comm);
}'''

PROBES: dict[str, tuple[tuple[str, str], ...]] = {
    "process_exec": (("execve tracepoint", _EXEC_PRIMARY),),
    "file_write": (("openat write-flag tracepoint", _WRITE_PRIMARY),),
    "socket_connect": (
        ("connect tracepoint with IPv4+IPv6 sockaddr", _CONNECT_DUAL),
        ("connect tracepoint with IPv4 sockaddr only", _CONNECT_PRIMARY),
        ("connect tracepoint without destination", _CONNECT_FALLBACK),
    ),
}

TAGS = {"X": "process_exec", "W": "file_write", "C": "socket_connect",
        "6": "socket_connect"}

# Trần phát mỗi giây cho mỗi loại. `openat` và `connect` có thể bùng lên khi
# một tiến trình duyệt cả cây thư mục hay quét cổng. Chặn ở đây, và ĐẾM số bị
# bỏ — mất log mà không có bộ đếm là mất log trong im lặng.
RATE_LIMIT_PER_S = {"process_exec": 200, "file_write": 300, "socket_connect": 200}


@dataclass
class ProbeSupport:
    """Loại event nào thật sự gắn được vào kernel này."""

    supported: dict[str, str] = field(default_factory=dict)   # kind -> tên phương án
    unsupported: dict[str, str] = field(default_factory=dict)  # kind -> lý do

    def kinds(self) -> frozenset[str]:
        return frozenset(self.supported)

    def to_dict(self) -> dict:
        return {"supported": dict(self.supported), "unsupported": dict(self.unsupported)}


# Danh tính đã biết theo PID. Bảng này tồn tại vì một lý do đo được: trên máy
# thật, **62% event `process_exec` không đọc kịp /proc** — tiến trình đã chết
# trước khi Shield mở được `/proc/<pid>/stat`. Không có bảng này thì 62% telemetry
# tiến trình không vào được evidence graph và không ghép được chuỗi hành vi, vì
# danh tính "pid:unknown" gộp mọi tiến trình từng mang số đó lại làm một.
#
# Với `process_exec`, chính event ĐÓ là thời điểm tiến trình bắt đầu. Nên khi
# /proc không còn, mốc thời gian của event là một danh tính thay thế đúng về
# ngữ nghĩa: hai tiến trình cùng PID khởi động trong cùng một mili-giây là
# chuyện không xảy ra. Nó được đánh dấu `identity_source="exec_ts"` để không ai
# nhầm nó với start_ticks đọc được thật.
_IDENTITY_CACHE_MAX = 4096
_identity_cache: "OrderedDict[int, dict]" = OrderedDict()


def _read_proc_stat(pid: int, proc_root: Path) -> tuple[int, str] | None:
    """(ppid, start_ticks) từ `/proc/<pid>/stat`. None nếu không đọc được."""
    try:
        stat = (proc_root / str(pid) / "stat").read_text(errors="replace")
        end = stat.rfind(")")
        fields = stat[end + 2:].split()
        return int(fields[1]), fields[19]
    except (OSError, ValueError, IndexError):
        return None


def _read_proc_exe(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    """Đường dẫn executable từ `/proc/<pid>/exe`. None nếu không đọc được.

    Trả về ĐÚNG chuỗi kernel đưa ra, không dọn dẹp:

    - Kernel giải quyết symlink về binary thật, nên chạy qua `/bin/sleep` ghi
      thành `/usr/lib/cargo/bin/coreutils/sleep`. Đường dẫn đó không khớp thứ
      người dùng gõ, và đó chính là điều đáng ghi: symlink không giả mạo được
      danh tính executable.
    - Executable đã bị xoá cho hậu tố `" (deleted)"`. GIỮ NGUYÊN. Một tiến
      trình đang chạy từ binary đã biến mất là dấu hiệu điều tra cổ điển; cắt
      hậu tố cho "sạch đường dẫn" là xoá đúng thứ đáng báo.

    Không đọc được thì là không biết, và không biết thì không đoán — `comm`
    KHÔNG được dùng thay: nó bị kernel cắt còn 15 ký tự và bị dùng chung giữa
    các binary khác nhau (đo trên máy thật: `ThreadPoolForeg` ứng với cả
    `/usr/bin/opera` lẫn `/usr/bin/claude-desktop`).

    GIỚI HẠN: `exe` được đọc lúc PHÂN TÍCH DÒNG, chứ không phải lúc syscall xảy
    ra. bpftrace giao dòng NGAY — đo bằng `nsecs` của kernel, cả ba mode (mặc
    định, `-B line`, `-B none`) đều nhận được tức thì và giống hệt nhau — nên
    khoảng cách này bình thường là mili-giây. Nhưng nó không bằng không: nếu
    event loop bị chặn, các dòng chờ trong pipe và được đọc muộn. Khi đó một
    tiến trình `exec()` giữa lúc connect và lúc đọc sẽ được ghi kèm binary SAU
    exec. Không bao giờ CŨ hơn thứ /proc xác nhận được, nhưng cũng không phải
    ảnh chụp tại thời điểm syscall. Một tiến trình chết ngay sau `connect()`
    không kịp có executable — quan sát được là hai event đúng PID với `exe`
    vắng mặt. Đó là fail closed và đúng; nhưng nó cũng có nghĩa là **vắng mặt
    `exe` không phải bằng chứng về gì cả**, chỉ là tiến trình đã biến mất
    trước khi hỏi kịp. Cùng lý do đó, một tiến trình `exec()` rồi chết ngay có
    thể để lại `exe` của lượt đọc TRƯỚC (từ bảng nhớ, đường dự phòng ở
    `_identity`) — bảng nhớ giữ ảnh chụp cuối đọc được, và khi /proc đã biến
    mất thì không còn gì để đối chiếu.
    """
    try:
        return os.readlink(proc_root / str(pid) / "exe")[:4096]
    except OSError:
        # ENOENT tiến trình đã thoát hoặc là kernel thread; EPERM không đủ
        # quyền; EINVAL không phải symlink. Cả ba đều là "không biết".
        return None


def _read_proc_identity(pid: int, proc_root: Path = Path("/proc")) -> dict | None:
    parsed = _read_proc_stat(pid, proc_root)
    if parsed is None:
        return None
    ppid, start_ticks = parsed
    identity = {"ppid": ppid, "start_ticks": start_ticks,
                "process_identity": f"{pid}:{start_ticks}", "identity_source": "proc"}
    # Đọc trong CÙNG lượt resolve, không thêm lượt đi /proc riêng. Đo trên máy
    # thật: `readlink` mất 1,54 µs so với 11,89 µs của lần đọc `stat` ngay bên
    # trên — rẻ hơn 7,8 lần một thứ đã chạy sẵn hai lần mỗi event.
    exe = _read_proc_exe(pid, proc_root)
    if exe is not None:
        identity["exe"] = exe
    # DANH TÍNH CỦA CHA, không chỉ số PID của cha.
    #
    # `resolver._process_key` từ chối dựng thực thể tiến trình khi không có
    # start_ticks — vì PID được Linux dùng lại, nên "pid 4321 trên máy này" gộp
    # mọi tiến trình từng mang số đó làm một. Quy tắc đó đúng, và nó áp cho cả
    # tiến trình CHA.
    #
    # Hậu quả trước khi có mấy dòng này, đo trên dữ liệu thật: 615.580 event
    # `process_exec` sinh ra ĐÚNG 0 cạnh `spawned`. Mã dựng cây tiến trình đã
    # tồn tại trong resolver từ 2.0 và chưa bao giờ chạy — cùng kiểu hỏng với
    # `BehaviorChainDetector`: khai một khả năng, thiếu một mắt xích, không ai
    # biết vì phần còn lại vẫn xanh.
    #
    # Cha thường sống lâu hơn con (shell, systemd, trình duyệt) nên lần đọc
    # này gần như luôn thành công, và bảng nhớ dưới đây làm nó gần như miễn phí
    # cho những lần sau.
    parent = _parent_identity(ppid, proc_root)
    if parent:
        identity["parent_start_ticks"] = parent
    return identity


def _parent_identity(ppid: int, proc_root: Path = Path("/proc")) -> str:
    """`start_ticks` của tiến trình cha. Rỗng nếu không đọc được — KHÔNG đoán.

    CỐ Ý KHÔNG có bảng nhớ ở đây, dù cha thường sống lâu và bảng nhớ sẽ trúng
    gần như mọi lần. Lý do: PID được dùng lại. Một mục nhớ `ppid -> ticks` trở
    thành SAI ngay khi tiến trình cha chết và số PID đó được cấp cho tiến trình
    khác — và cái sai đó là gộp hai tiến trình cha khác nhau làm một, đúng thứ
    `_process_key` tồn tại để chặn. Kiểm lại mục nhớ thì phải đọc `/proc`, tức
    là mất luôn cái lợi.

    Chi phí thật: một lần `read()` cho mỗi event, trần tốc độ đã chặn ở 200/s
    mỗi loại. Trên dữ liệu thật đó là ~0,4 lần đọc mỗi giây.
    """
    if ppid <= 0:
        return ""
    parsed = _read_proc_stat(ppid, proc_root)
    return parsed[1] if parsed is not None else ""


def _remember(pid: int, identity: dict) -> dict:
    _identity_cache[pid] = identity
    _identity_cache.move_to_end(pid)
    while len(_identity_cache) > _IDENTITY_CACHE_MAX:
        _identity_cache.popitem(last=False)
    return identity


def _identity(pid: int, kind: str = "", ts: float = 0.0,
              proc_root: Path = Path("/proc")) -> dict:
    """Danh tính ổn định cho một PID, dùng chung cho cả ba loại event."""
    live = _read_proc_identity(pid, proc_root)

    if kind == "process_exec":
        # Lượt exec đặt LẠI danh tính cho PID này, kể cả khi bảng đang giữ một
        # giá trị cũ: cùng PID sau một lượt exec là một tiến trình khác.
        #
        # BỎ `exe` đọc từ /proc ở đây, và đây là chỗ dễ sai nhất của cả thay
        # đổi này. Probe bắt ở `sys_enter_execve`, tức TRƯỚC khi exec xảy ra —
        # `/proc/<pid>/exe` lúc đó vẫn trỏ vào binary CŨ, còn `data["exe"]` từ
        # bpftrace là binary SẮP chạy. Vì `data.update(_identity(...))` để
        # identity ghi đè, giữ `exe` ở đây sẽ thay đường dẫn đúng bằng đường
        # dẫn của tiến trình gọi. Không nhớ nó vào bảng luôn: một mục nhớ mang
        # binary cũ sẽ rò rỉ sang các event sau của cùng PID.
        if live is not None:
            live.pop("exe", None)
            return _remember(pid, live)
        return _remember(pid, {
            "ppid": 0, "start_ticks": "", "identity_source": "exec_ts",
            "process_identity": f"{pid}:x{int((ts or time.time()) * 1000)}",
        })

    if live is not None:
        cached = _identity_cache.get(pid)
        # /proc đọc được là bằng chứng trực tiếp và thắng bảng nhớ — trừ khi
        # bảng nhớ đang giữ đúng cùng một tiến trình, khi đó giữ nguyên để mọi
        # event của tiến trình đó mang cùng một danh tính.
        if cached and cached.get("process_identity") == live["process_identity"]:
            # `exe` là ngoại lệ, vì `process_identity` KHÔNG chứng minh được
            # executable không đổi: đo trên máy thật, `exec()` giữ nguyên
            # `start_ticks` (8888000 trước và sau), nên cùng một
            # `pid:start_ticks` vẫn có thể đang chạy binary khác. Bảng nhớ
            # được phép giữ ảnh chụp danh tính, nhưng không được trở thành
            # bằng chứng mới hơn /proc.
            refreshed = dict(cached)
            if "exe" in live:
                refreshed["exe"] = live["exe"]
            else:
                # /proc đọc được `stat` nhưng không đọc được `exe`: không biết,
                # và không biết thì bỏ đi chứ không giữ giá trị cũ làm nền.
                refreshed.pop("exe", None)
            return _remember(pid, refreshed)
        return _remember(pid, live)

    cached = _identity_cache.get(pid)
    if cached is not None:
        _identity_cache.move_to_end(pid)
        return cached
    # Chưa từng thấy lượt exec của PID này và /proc đã biến mất: thành thật
    # nói là không biết. Danh tính "unknown" bị resolver loại khỏi graph, và
    # đó là hành vi đúng — một node gộp nhầm còn tệ hơn một node thiếu.
    return {"ppid": 0, "start_ticks": "", "identity_source": "unknown",
            "process_identity": f"{pid}:unknown"}


async def probe_support(timeout_s: float = 20.0) -> ProbeSupport:
    """Thử gắn thật từng đoạn chương trình vào kernel và xem cái nào sống.

    `--dry-run` của bpftrace gắn hết probe rồi thoát ngay: nó kiểm cả biên dịch
    lẫn quyền và sự tồn tại của tracepoint — đúng ba thứ có thể khác nhau giữa
    hai máy. Đây là lý do năng lực phải được ĐO chứ không suy ra từ việc
    `/sys/kernel/btf/vmlinux` có tồn tại hay không.
    """
    support = ProbeSupport()
    for kind, variants in PROBES.items():
        for label, program in variants:
            ok, detail = await _try_attach(program, timeout_s)
            if ok:
                support.supported[kind] = label
                break
            support.unsupported[kind] = f"{label}: {detail}"
            logger.info("Probe %s (%s) không gắn được: %s", kind, label, detail)
        if kind in support.supported:
            support.unsupported.pop(kind, None)
    return support


async def _try_attach(program: str, timeout_s: float) -> tuple[bool, str]:
    try:
        process = await asyncio.create_subprocess_exec(
            "bpftrace", "-q", "--dry-run", "-e", program,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return False, str(exc)
    try:
        _, stderr = await asyncio.wait_for(process.communicate(), timeout_s)
    except TimeoutError:
        process.kill()
        await process.wait()
        return False, "hết thời gian chờ khi gắn probe"
    if process.returncode != 0:
        return False, stderr.decode(errors="replace").strip()[:400] or f"bpftrace thoát {process.returncode}"
    return True, "ok"


def build_program(kinds) -> str:
    """Ghép các đoạn được hỗ trợ thành MỘT chương trình.

    Một tiến trình bpftrace thay vì ba: ba tiến trình nghĩa là ba lần chi phí
    gắn probe, ba chỗ có thể chết riêng lẻ, và ba trạng thái sức khoẻ phải đồng
    bộ với nhau.
    """
    chosen = []
    for kind, variants in PROBES.items():
        if kind not in kinds:
            continue
        label = kinds[kind] if isinstance(kinds, dict) else None
        program = next((p for name, p in variants if label is None or name == label), variants[0][1])
        chosen.append(program)
    return "\n".join(chosen)


def _ipv6_from_words(words) -> str | None:
    """Bốn từ 32 bit như bpftrace in ra -> chuỗi IPv6 chuẩn tắc.

    Mỗi từ là bốn byte liên tiếp của địa chỉ, đọc theo thứ tự byte của MÁY.
    Kiểm ngược trên dữ liệu thật: `::1` in ra `00000000 00000000 00000000
    01000000`, dựng lại đúng `::1`.

    KHÔNG quy `::ffff:127.0.0.1` về `127.0.0.1`: đó là hai cách viết mà kernel
    phân biệt được, và một luật quy đổi ngầm sẽ làm người điều tra đọc sai thứ
    tiến trình thực sự yêu cầu.
    """
    try:
        raw = b"".join(struct.pack("<I", int(word, 16) & 0xFFFFFFFF) for word in words)
        return str(ipaddress.IPv6Address(raw))
    except (ValueError, struct.error):
        return None


def parse_line(line: str) -> tuple[str, dict] | None:
    """Một dòng bpftrace -> (kind, data). None nếu dòng không dùng được.

    Hàm thuần, tách riêng để test được toàn bộ việc phân tích mà không cần
    root: đây là chỗ dữ liệu từ kernel đi vào Shield, nên nó phải chịu được
    dòng cụt, dòng thừa cột và tên file có ký tự lạ.
    """
    parts = line.rstrip("\n").split("\t")
    kind = TAGS.get(parts[0]) if parts else None
    if kind is None or len(parts) < 4:
        return None
    try:
        pid, uid = int(parts[1]), int(parts[2])
    except ValueError:
        return None
    if pid <= 0:
        return None
    data: dict = {"pid": pid, "uid": uid, "comm": parts[3][:256], "telemetry_backend": "ebpf"}
    if kind == "process_exec":
        if len(parts) < 5:
            return None
        data["exe"] = parts[4][:4096]
    elif kind == "file_write":
        if len(parts) < 5:
            return None
        data["path"] = parts[4][:4096]
    elif parts[0] == "6":
        # IPv6: probe phát BỐN TỪ 32 BIT thô, không phát chuỗi.
        #
        # `ntop()` trả về "::" cho mọi địa chỉ IPv6 trên kernel này — xác minh
        # bằng bốn biến thể chương trình: nguyên bản, `uptr()`, khai họ tường
        # minh, và cả hai. Nguyên nhân đo được: bpftrace đọc VÔ HƯỚNG từ vùng
        # nhớ người dùng thì được, đọc MẢNG thì trả về số 0. Cổng (2 byte) và
        # `u6_addr32[i]` (4 byte) đều đúng; `u6_addr8[i]` và cả `struct` copy
        # đều ra 0.
        #
        # `::` là một địa chỉ IPv6 HỢP LỆ (unspecified), nên lỗi này không tự
        # lộ ra: nó ghi mọi kết nối IPv6 là đi tới `::` và mọi test tổng hợp
        # vẫn xanh.
        #
        # Dựng chuỗi ở đây, bằng Python, cũng tốt hơn: nó kiểm được bằng unit
        # test không cần root, thay vì phụ thuộc hành vi `ntop()` của từng bản
        # bpftrace.
        if len(parts) < 9:
            return None
        address = _ipv6_from_words(parts[4:8])
        if address is None:
            return None
        data["remote_ip"] = address
        try:
            data["remote_port"] = int(parts[8])
        except ValueError:
            return None
    elif kind == "socket_connect":
        if len(parts) >= 6:
            data["remote_ip"] = parts[4][:64]
            try:
                data["remote_port"] = int(parts[5])
            except ValueError:
                return None
        else:
            # Phương án dự phòng: biết có kết nối, không biết tới đâu. Ghi rõ
            # để không ai đọc nhầm "thiếu địa chỉ" thành "kết nối nội bộ".
            data["destination_known"] = False
    return kind, data


def _report(store, support: ProbeSupport, running: bool, detail: str,
            dropped: dict[str, int] | None = None) -> None:
    """Ghi coverage THEO TỪNG LOẠI event vào collector health.

    Một dòng sức khoẻ chung cho "kernel_telemetry" không trả lời được câu hỏi
    người vận hành thật sự cần: chuỗi hành vi có chạy được không. Ba dòng riêng
    thì trả lời được, và trả lời sai thì nhìn thấy ngay.

    CỐ Ý không ghi vào hàng "kernel_telemetry": hàng đó thuộc về
    CollectorSupervisor, và nó ghi đè bằng "collector running" vài giây một
    lần. Hai bên cùng ghi một hàng nghĩa là bên nào ghi sau thắng — số event bị
    bỏ do giới hạn tốc độ đã biến mất đúng như vậy trên máy thật. Số bị bỏ giờ
    nằm trong hàng của CHÍNH loại bị bỏ, nơi không ai tranh.
    """
    if store is None:
        return
    # `None` và `{}` KHÔNG giống nhau ở đây, và gộp chúng lại là cách con số
    # cộng dồn đi giật lùi: `None` nghĩa là "lượt này không biết, giữ nguyên số
    # cũ", còn `{}` nghĩa là "biết chắc, và bằng không". Lượt báo lúc khởi động
    # truyền `{}` để đặt lại về 0 — bộ đếm của RateLimiter sống theo tiến
    # trình, nên giữ tổng của lần chạy trước sẽ khiến con số tụt xuống ngay khi
    # có lượt bỏ đầu tiên của tiến trình mới.
    for kind in PROBES:
        available = running and kind in support.supported
        if available:
            text = support.supported.get(kind, "")
            if (dropped or {}).get(kind):
                text += f" — đã bỏ {dropped[kind]} event do giới hạn tốc độ"
        else:
            text = support.unsupported.get(kind, detail or "chưa gắn được probe")
        # Số bỏ KHÔNG đổi `available`: chạm trần trong một chớp lưu lượng không
        # có nghĩa là probe đã tắt.
        store.set_collector_health(
            f"kernel_telemetry.{kind}", "ebpf", available, text,
            dropped_events=None if dropped is None else dropped.get(kind, 0))
    # Mục 0.4: không tuyên bố chuỗi hành vi hoạt động nếu thiếu một mắt xích.
    # Đây là dòng người vận hành cần nhìn: "có ba loại telemetry" không trả lời
    # được câu "chuỗi exec->write->connect có chạy không".
    status = chain_status(support)
    store.set_collector_health(
        "behavior_chain", "ebpf", running and status["active"],
        "exec -> write -> connect đang hoạt động" if running and status["active"]
        else (status["reason"] or "telemetry nhân chưa chạy"),
    )


def chain_status(support: ProbeSupport) -> dict:
    """Chuỗi hành vi có đủ mắt xích không — dùng cho UI và health.

    Mục 0.4: "Không tuyên bố behavior chain active nếu thiếu một mắt xích."
    """
    from shield.security.mitre import BehaviorChainDetector

    required = frozenset(BehaviorChainDetector.ORDER)
    missing = sorted(required - support.kinds())
    return {
        "active": not missing,
        "required": sorted(required),
        "covered": sorted(support.kinds() & required),
        "missing": missing,
        "reason": "" if not missing else
                  "thiếu telemetry cho: " + ", ".join(missing),
    }


async def ebpf_exec_loop(event_bus, store=None) -> None:
    """Chạy một chương trình bpftrace cố định; không bao giờ nhận mã từ IPC/config."""
    support = await probe_support()
    if not support.supported:
        detail = "; ".join(f"{k}: {v}" for k, v in support.unsupported.items())[:400]
        logger.warning("Không gắn được probe eBPF nào: %s", detail)
        _report(store, support, False, detail or "bpftrace không khả dụng")
        return

    status = chain_status(support)
    if not status["active"]:
        # Nói ra ngay lúc khởi động, không đợi ai đó thắc mắc vì sao chuỗi hành
        # vi chưa từng kêu.
        logger.warning("Chuỗi hành vi KHÔNG hoạt động: %s", status["reason"])

    program = build_program(support.supported)
    try:
        process = await asyncio.create_subprocess_exec(
            "bpftrace", "-q", "-e", program,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            limit=64 * 1024,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        _report(store, support, False, str(exc))
        return

    covered = ", ".join(sorted(support.supported))
    # `{}` chứ không phải mặc định: tiến trình mới, bộ đếm mới, số phải về 0.
    _report(store, support, True, f"bpftrace đang chạy: {covered}", {})
    logger.info("Telemetry eBPF: %s%s", covered,
                "" if status["active"] else f" (chuỗi hành vi TẮT — {status['reason']})")

    limiter = RateLimiter(RATE_LIMIT_PER_S)
    last_drop_report = time.monotonic()
    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            parsed = parse_line(line.decode(errors="replace"))
            if parsed is None:
                continue
            kind, data = parsed
            at = now()
            if not limiter.allow(kind, at):
                continue
            data.update(_identity(data["pid"], kind, at))
            await event_bus.publish(Event(at, "kernel", kind, data))

            # Số bị bỏ phải nổi lên chỗ nhìn thấy được. Giới hạn tốc độ mà
            # không báo là một dạng mất dữ liệu trong im lặng.
            if limiter.dropped and time.monotonic() - last_drop_report > 60:
                last_drop_report = time.monotonic()
                _report(store, support, True, f"bpftrace đang chạy: {covered}",
                        dict(limiter.dropped))
    finally:
        if process.returncode is None:
            process.terminate()
            await process.wait()
        stderr = (await process.stderr.read()).decode(errors="replace")[:1000]
        _report(store, support, False, stderr.strip() or f"bpftrace thoát {process.returncode}")
