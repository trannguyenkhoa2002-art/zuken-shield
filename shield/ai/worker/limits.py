"""Trần tài nguyên CỨNG cho tiến trình worker.

`asyncio.wait_for` quanh một coroutine KHÔNG phải một giới hạn tài nguyên. Nó
bỏ chờ; tiến trình bên kia vẫn quay CPU, vẫn cấp phát bộ nhớ, vẫn giữ file
descriptor. Với một model treo, thứ đó chỉ có nghĩa là agent thôi nhìn vào một
đám cháy vẫn đang cháy.

Nên trần ở đây do KERNEL thi hành, không do Python:

- `RLIMIT_AS` — cấp phát vượt trần trả `MemoryError`/`ENOMEM` ngay trong worker.
- `RLIMIT_CPU` — vượt thời gian CPU thì kernel giết, kể cả khi worker đang ở
  trong một vòng lặp chặt không bao giờ trả điều khiển.
- `RLIMIT_NPROC` — chặn fork bomb.
- `RLIMIT_FSIZE` — worker không ghi file lớn nào; đặt 0 nghĩa là không ghi gì.
- `RLIMIT_CORE` — không sinh core dump. Một core dump của tiến trình model là
  một bản sao dữ liệu điều tra nằm trên đĩa mà không ai quản.

**Vì sao worker tự áp trần cho chính nó thay vì cha áp qua `preexec_fn`:**
`preexec_fn` chạy giữa `fork()` và `exec()` trong một tiến trình ĐA LUỒNG —
agent dùng `asyncio.to_thread` khắp nơi — và CPython ghi rõ nó không an toàn ở
đó (khoá bị giữ bởi một luồng khác không bao giờ được nhả trong con). Đổi lại,
`limits.apply()` chạy là dòng đầu tiên của worker shim, TRƯỚC khi bất kỳ mã
model nào được nạp. Mã không đáng tin không có cơ hội chạy trước khi trần đã
xuống. Trần chỉ hạ được, không nâng lại, vì hard limit cũng bị đặt cùng lúc.
"""

from __future__ import annotations

import dataclasses
import json
import resource

# Mặc định. Đủ rộng cho một model local nhỏ, đủ chặt để một worker chạy loạn
# không đụng tới trần `MemoryMax=1G` của cả service agent.
DEFAULT_MEMORY_BYTES = 512 * 1024 * 1024
DEFAULT_CPU_SECONDS = 30
DEFAULT_PROCESSES = 64
DEFAULT_OPEN_FILES = 128


@dataclasses.dataclass(frozen=True)
class ResourceLimits:
    memory_bytes: int = DEFAULT_MEMORY_BYTES
    cpu_seconds: int = DEFAULT_CPU_SECONDS
    processes: int = DEFAULT_PROCESSES
    open_files: int = DEFAULT_OPEN_FILES

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "ResourceLimits":
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) - {f.name for f in dataclasses.fields(cls)}:
            raise ValueError("mô tả trần tài nguyên không hợp lệ")
        # Kẹp về khoảng hợp lý ở CẢ HAI đầu. Một trần 0 làm worker chết ngay
        # lúc khởi động và trông giống hệt một model hỏng; một trần khổng lồ
        # thì không còn là trần.
        return cls(
            # 0 đi thẳng qua: đó là "cgroup lo bộ nhớ", không phải một trần bé.
            memory_bytes=(0 if int(data.get("memory_bytes", DEFAULT_MEMORY_BYTES)) == 0
                          else max(64 * 1024 * 1024,
                                   min(int(data.get("memory_bytes", DEFAULT_MEMORY_BYTES)),
                                       8 * 1024 ** 3))),
            cpu_seconds=max(1, min(int(data.get("cpu_seconds", DEFAULT_CPU_SECONDS)), 3600)),
            processes=max(1, min(int(data.get("processes", DEFAULT_PROCESSES)), 4096)),
            open_files=max(16, min(int(data.get("open_files", DEFAULT_OPEN_FILES)), 65536)),
        )


def apply(limits: ResourceLimits) -> list[str]:
    """Hạ trần cho CHÍNH tiến trình đang chạy. -> danh sách trần đã áp được.

    Không ném khi một trần riêng lẻ không áp được: một số môi trường (container
    đã siết sẵn, kernel không có `RLIMIT_NPROC`) từ chối hạ thêm. Áp được ba
    trong bốn vẫn tốt hơn là worker không chạy — và cái không áp được phải
    được BÁO CÁO, không được im lặng biến mất, nên hàm trả về danh sách.
    """
    applied: list[str] = []
    wanted = (
        # `memory_bytes = 0` nghĩa là CGROUP SỞ HỮU BỘ NHỚ, không phải "không
        # có trần". Đo được trên llama.cpp: VmPeak ~3,2 GiB đặt chỗ trong khi
        # cgroup chỉ bị tính ~0,9–2,0 GiB thật sự chạm tới. `RLIMIT_AS` đếm
        # phần đặt chỗ, nên nó hoặc chặn model nạp, hoặc phải lỏng tới mức
        # không còn là trần. `memory.max` đếm đúng thứ đáng đếm.
        ("RLIMIT_AS", limits.memory_bytes),
        ("RLIMIT_CPU", limits.cpu_seconds),
        ("RLIMIT_NPROC", limits.processes),
        ("RLIMIT_NOFILE", limits.open_files),
        # Worker không ghi file. Trần 0 làm mọi lần ghi hỏng ngay thay vì để
        # một model đầy sáng tạo đổ dữ liệu điều tra ra đĩa.
        ("RLIMIT_FSIZE", 0),
        ("RLIMIT_CORE", 0),
    )
    for name, value in wanted:
        if name == "RLIMIT_AS" and not value:
            continue
        which = getattr(resource, name, None)
        if which is None:
            continue
        try:
            soft, hard = resource.getrlimit(which)
            # Đặt CẢ hard limit: chỉ hạ soft thì mã model nâng lại được bằng
            # một dòng `setrlimit`, và một trần nâng lại được không phải trần.
            target = value if hard in (resource.RLIM_INFINITY, -1) else min(value, hard)
            resource.setrlimit(which, (target, target))
            applied.append(name)
        except (ValueError, OSError):
            continue
    return applied


# Người dùng hệ thống mà worker hạ quyền xuống khi agent chạy bằng root.
# `nobody` là mặc định vì nó có mặt trên mọi bản Linux; gói cài đặt có thể tạo
# một user riêng và trỏ biến này vào đó.
WORKER_USER_ENV = "SHIELD_AI_WORKER_USER"
DEFAULT_WORKER_USER = "nobody"


def drop_privileges(username: str = "") -> dict:
    """Hạ quyền cho CHÍNH tiến trình worker. -> mô tả việc đã làm.

    `shield-agent.service` chạy `User=root` — nó cần root cho tcpdump, nftables
    và sniff. Tiến trình con thừa hưởng điều đó, nên nếu không làm gì thì mã
    model chạy bằng **root**. Mô hình đe doạ của Phase 3C nói mã model là
    compute KHÔNG ĐÁNG TIN; chạy compute không đáng tin bằng root làm ranh giới
    tiến trình gần như vô nghĩa — nó chặn được model ăn RAM, không chặn được
    model đọc mọi thứ trên máy.

    Thứ tự BẮT BUỘC: `setgroups` -> `setgid` -> `setuid`. Làm ngược lại thì sau
    `setuid` tiến trình không còn quyền bỏ group phụ, và nó giữ lại nhóm của
    root — một lần hạ quyền trông như đã xong nhưng chưa.

    Không ném khi không hạ được: agent chạy non-root (lúc phát triển, lúc chạy
    test) thì không có gì để hạ, và đó không phải lỗi. Nhưng kết quả phải được
    BÁO CÁO, không im lặng — "đã hạ quyền" và "không cần hạ" và "hạ thất bại"
    là ba việc khác nhau.
    """
    import os

    if os.geteuid() != 0:
        return {"dropped": False, "reason": "not_root", "uid": os.geteuid()}

    import pwd

    name = username or os.environ.get(WORKER_USER_ENV, "") or DEFAULT_WORKER_USER
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return {"dropped": False, "reason": "unknown_user", "user": name}

    try:
        os.setgroups([])
        os.setgid(entry.pw_gid)
        os.setuid(entry.pw_uid)
    except OSError as exc:
        return {"dropped": False, "reason": f"failed:{type(exc).__name__}", "user": name}

    if os.geteuid() == 0 or os.getuid() == 0:
        # Hạ quyền "thành công" mà vẫn còn root là trạng thái tệ nhất: mọi thứ
        # phía sau tin rằng ranh giới đã dựng. Nói thẳng là chưa.
        return {"dropped": False, "reason": "still_root", "user": name}
    return {"dropped": True, "user": name, "uid": os.getuid(), "gid": os.getgid()}
