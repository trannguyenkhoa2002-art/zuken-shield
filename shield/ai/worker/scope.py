"""Đưa worker model RA NGOÀI cgroup của agent (Phase 3C-1).

Phase 3C-0 đo được điều này: `RLIMIT_AS` là công cụ SAI cho llama.cpp. Nó đếm
địa chỉ ảo đã ĐẶT CHỖ, và llama.cpp đặt chỗ ~3,3 GiB trong khi thực dùng ~2,0
GiB. Đặt trần theo `RLIMIT_AS` nghĩa là hoặc model không nạp được, hoặc trần
lỏng tới mức vô nghĩa.

Thứ đếm đúng là cgroup: `memory.max` tính bộ nhớ THẬT SỰ chạm tới, và kernel
giết đúng cgroup vượt trần chứ không chọn nạn nhân trên cả máy.

Nhưng có một cái bẫy: một cgroup con NẰM TRONG `shield-agent.service` vẫn bị
`MemoryMax=1G` của service bao ngoài, nên model 2 GiB vẫn không chạy được và
tệ hơn — nó ăn vào ngân sách bộ nhớ của chính agent. Vì thế scope phải là
**ANH EM**, không phải con:

    /system.slice/shield-agent.service          MemoryMax=1G   (không đổi)
    /system.slice/shield-ai-worker-<id>.scope   MemoryMax=...  (model ở đây)

`systemd-run --scope` đặt unit tạm dưới `system.slice` chứ không lồng vào unit
gọi nó — đã đo, không phải suy đoán.

Và nếu KHÔNG dựng được scope: **model bị tắt**. Không có đường "chạy tạm trong
cgroup của agent" — đó chính là thứ cả file này tồn tại để ngăn.
"""

from __future__ import annotations

import os
import re
import uuid

from shield.ai.worker.trusted import UntrustedExecutable, validate_executable

# Đường dẫn tuyệt đối, không tra PATH. `PATH` là biến môi trường, và một thứ kẻ
# tấn công đặt được không được quyết định binary nào chạy bằng root.
SYSTEMD_RUN_CANDIDATES = ("/usr/bin/systemd-run", "/bin/systemd-run")
SYSTEMCTL_CANDIDATES = ("/usr/bin/systemctl", "/bin/systemctl")

# Tên thuộc tính systemd được phép đặt. Danh sách ĐÓNG, và nó phải đóng: tên
# thuộc tính đi thẳng vào dòng lệnh của một tiến trình chạy bằng root, nên một
# tên đến từ cấu hình người dùng là một đường tiêm lệnh.
ALLOWED_PROPERTIES = frozenset({
    "MemoryMax", "MemorySwapMax", "CPUQuota", "TasksMax",
})

_UNIT_NAME = re.compile(r"^[a-z0-9-]{1,64}$")
_PROPERTY_VALUE = re.compile(r"^[A-Za-z0-9%.]{1,32}$")


class ScopeUnavailable(RuntimeError):
    """Không dựng được scope. Model bị TẮT, không chạy kèm agent."""



def find_systemd_run() -> str:
    """`systemd-run` đã qua chính sách tin cậy, hoặc rỗng."""
    for candidate in SYSTEMD_RUN_CANDIDATES:
        try:
            return str(validate_executable(candidate))
        except UntrustedExecutable:
            continue
    return ""


def unit_name(prefix: str = "shield-ai-worker") -> str:
    """Tên unit đoán trước được, duy nhất mỗi lượt.

    Đoán trước được để người vận hành `systemctl status` được nó lúc đang chạy;
    duy nhất để hai lượt không đụng nhau. `--collect` dọn unit khi nó thoát, kể
    cả khi thoát vì lỗi — không có `--collect` thì một unit hỏng nằm lại mãi và
    lần sau trùng tên sẽ hỏng vì lý do không liên quan.
    """
    name = f"{prefix}-{uuid.uuid4().hex[:12]}"
    if not _UNIT_NAME.match(name):
        raise ScopeUnavailable(f"tên unit không hợp lệ: {name!r}")
    return name


def properties(*, memory_max: str, cpu_quota: str, tasks_max: str) -> list[str]:
    """-> danh sách `--property=K=V` đã kiểm CẢ tên lẫn giá trị."""
    wanted = {
        "MemoryMax": memory_max,
        # Không cho tràn sang swap: một model bị đẩy ra swap không bị giết, nó
        # chỉ chậm đi hàng chục lần và kéo theo cả đĩa. Trần bộ nhớ mà còn swap
        # thì không phải trần, chỉ là một lời đề nghị.
        "MemorySwapMax": "0",
        "CPUQuota": cpu_quota,
        "TasksMax": tasks_max,
    }
    out = []
    for key, value in wanted.items():
        if key not in ALLOWED_PROPERTIES:
            raise ScopeUnavailable(f"thuộc tính không được phép: {key!r}")
        if not _PROPERTY_VALUE.match(str(value)):
            raise ScopeUnavailable(f"giá trị thuộc tính không hợp lệ: {key}={value!r}")
        out.append(f"--property={key}={value}")
    return out


def find_systemctl() -> str:
    for candidate in SYSTEMCTL_CANDIDATES:
        try:
            return str(validate_executable(candidate))
        except UntrustedExecutable:
            continue
    return ""


def stop_argv(unit: str, *, euid: int | None = None) -> tuple[str, ...]:
    """argv giết MỌI tiến trình trong scope, theo UNIT chứ không theo pid.

    Đây là bài học đắt nhất của phase này: `systemd-run --scope` THOÁT sau khi
    đăng ký scope, trong khi payload tiếp tục chạy bên trong cgroup. Giết pid ta
    cầm chỉ giết cái vỏ, và một worker phớt lờ SIGTERM sống sót nguyên vẹn
    trong một scope không ai còn nhớ — đã quan sát được đúng như vậy.

    cgroup mới là thứ biết ai đang ở trong nó, nên dọn dẹp phải hỏi cgroup.
    """
    binary = find_systemctl()
    if not binary:
        raise ScopeUnavailable("không tìm thấy systemctl ở đường dẫn tin cậy")
    if not _UNIT_NAME.match(str(unit).removesuffix(".scope")):
        raise ScopeUnavailable(f"tên unit không hợp lệ: {unit!r}")
    euid = os.geteuid() if euid is None else euid
    argv = [binary]
    if euid != 0:
        argv.append("--user")
    argv.extend(["kill", "--signal=SIGKILL", "--kill-whom=all", str(unit)])
    return tuple(argv)


def prefix(*, memory_max: str, cpu_quota: str, tasks_max: str,
           euid: int | None = None) -> tuple[tuple[str, ...], str]:
    """-> (argv chèn trước lệnh worker, tên unit). `ScopeUnavailable` nếu hỏng.

    Trả về CẢ tên unit vì dọn dẹp phải giết theo unit — xem `stop_argv`.

    KHÔNG có `shell=True`, không chuỗi lệnh, không tên thuộc tính từ cấu hình:
    mọi phần tử ở đây hoặc là hằng trong mã, hoặc đã qua regex.
    """
    binary = find_systemd_run()
    if not binary:
        raise ScopeUnavailable("không tìm thấy systemd-run ở đường dẫn tin cậy")
    euid = os.geteuid() if euid is None else euid
    name = unit_name()
    argv = [binary, "--scope", "--quiet", "--collect"]
    if euid != 0:
        # Máy phát triển: manager của người dùng. Cùng cơ chế cgroup v2, khác
        # slice. Production chạy `User=root` nên đi nhánh trên.
        argv.append("--user")
    argv.append(f"--unit={name}")
    argv.extend(properties(memory_max=memory_max, cpu_quota=cpu_quota,
                           tasks_max=tasks_max))
    return tuple(argv), f"{name}.scope"


# Biến môi trường `systemd-run --user` cần để tìm bus của user manager. CHỈ
# đường phát triển: production chạy `User=root` và dùng bus HỆ THỐNG ở một
# đường dẫn cố định, nên nó không cần biến nào — môi trường worker ở đó vẫn
# đúng 5 biến như hợp đồng 3C-0 mô tả.
_USER_BUS_ENV = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")


def launcher_env(*, euid: int | None = None, source: dict | None = None) -> dict:
    """Biến môi trường THÊM mà `systemd-run` cần. Rỗng khi chạy root.

    Trả về rỗng ở production có chủ ý: mỗi biến thêm vào là một đường dẫn kẻ
    tấn công không phải tự đoán ra, và ranh giới môi trường tối thiểu của 3C-0
    là thứ ta không muốn nới cho tiện.
    """
    import os as _os

    euid = _os.geteuid() if euid is None else euid
    if euid == 0:
        return {}
    source = _os.environ if source is None else source
    return {name: source[name] for name in _USER_BUS_ENV if source.get(name)}
