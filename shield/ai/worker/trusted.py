"""Chương trình nào worker được phép LÀ. Chính sách đường dẫn tin cậy (mục 4).

`WorkerSupervisor.command` là một seam có chủ ý — không có nó thì không chứng
minh được lớp này sống sót trước một worker thù địch. Nhưng một seam mà cấu
hình người dùng chạm tới được là một seam kẻ tấn công chạm tới được: đổi một
dòng trong config thành `/tmp/x` là chạy mã tuỳ ý bằng quyền của agent, tức là
**root**.

Nên đường vào production đi qua đúng file này, và nó đóng:

- Tuyệt đối. Không đường dẫn tương đối, không `..`, không symlink chưa giải.
- **Không tra PATH.** `PATH` là biến môi trường; một thứ kẻ tấn công đặt được
  không được quyết định binary nào chạy bằng root.
- Chủ sở hữu `root`, và không group/other-writable. Một binary ai cũng ghi
  được là một binary ai cũng thay được.
- Không `shell=True`, không chuỗi lệnh — luôn là argv dạng danh sách.

Thay binary runtime vẫn nằm trong tầm quan sát của Guardian theo đúng ngữ nghĩa
hiện có: nó hash file cài đặt và báo khi khác đi.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

# Nơi một runtime cục bộ được phép nằm. Danh sách ĐÓNG, và nó là chính sách:
# thêm một dòng ở đây là một quyết định về bảo mật.
#
# `/tmp`, `/home`, `/var/tmp` cố ý vắng mặt — chúng ghi được bởi người dùng
# thường, nên một binary ở đó không phải thứ root nên chạy.
TRUSTED_PREFIXES = (
    "/opt/shield",
    "/usr/lib/shield",
    "/usr/bin",
    "/usr/local/bin",
    "/usr/libexec",
    "/bin",
)


class UntrustedExecutable(RuntimeError):
    """Chương trình không đạt chính sách. Fail closed — không chạy."""


def validate_executable(path: str | os.PathLike, *,
                        prefixes: tuple[str, ...] = TRUSTED_PREFIXES,
                        require_root_owned: bool = True) -> Path:
    """-> đường dẫn đã giải, hoặc `UntrustedExecutable`.

    Giải symlink TRƯỚC khi kiểm, không sau: kiểm quyền trên một symlink là kiểm
    quyền của con trỏ chứ không phải của thứ sẽ thật sự chạy.
    """
    raw = Path(path)
    if not raw.is_absolute():
        raise UntrustedExecutable(f"đường dẫn phải tuyệt đối: {raw}")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise UntrustedExecutable(f"không giải được đường dẫn: {raw} ({type(exc).__name__})") from exc

    if not any(resolved == Path(p) or resolved.is_relative_to(p) for p in prefixes):
        raise UntrustedExecutable(f"{resolved} nằm ngoài các thư mục tin cậy")

    info = resolved.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise UntrustedExecutable(f"{resolved} không phải file thường")
    if not os.access(resolved, os.X_OK):
        raise UntrustedExecutable(f"{resolved} không thực thi được")
    if require_root_owned and info.st_uid != 0:
        raise UntrustedExecutable(f"{resolved} không thuộc sở hữu root (uid={info.st_uid})")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        # Ghi được bởi group/other nghĩa là thay được bởi group/other.
        raise UntrustedExecutable(f"{resolved} cho phép group/other ghi")

    # Mọi thư mục trên đường đi cũng phải không ghi được bởi người ngoài: thay
    # được thư mục là thay được file bên trong, và lúc đó kiểm file là vô nghĩa.
    for parent in [resolved.parent, *resolved.parents]:
        try:
            pinfo = parent.lstat()
        except OSError:
            break
        if pinfo.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not (pinfo.st_mode & stat.S_ISVTX):
            raise UntrustedExecutable(f"thư mục {parent} ai cũng ghi được")
        if parent == Path("/"):
            break
    return resolved
