"""Mặc định KHÔNG MẠNG cho tiến trình model (điều kiện bắt buộc của 3C).

3C-0 đã đo và ghi rõ: worker vẫn mở được TCP ra Internet. Đó là giới hạn duy
nhất được nêu như điều kiện phải đóng trước khi có model thật, và lý do rất cụ
thể — một model có mạng là một model exfiltrate được. Mọi thứ nó vừa đọc là
telemetry của một endpoint đang bị điều tra, và ranh giới tiến trình không có
nghĩa lý gì nếu dữ liệu đi ra bằng cổng 443.

Runtime chạy TRONG worker (llama.cpp) không cần mạng để suy luận. Nên câu trả
lời đúng không phải "lọc" mà là **cắt hẳn**: một network namespace mới, rỗng,
chỉ có `lo` chưa bật. Không có route, không có DNS, không có gì để lọc sai.

Hai đường, cùng một kết quả do KERNEL thi hành:

1. **`os.unshare(CLONE_NEWNET)`** — production. `shield-agent.service` chạy
   `User=root`, nên worker có CAP_SYS_ADMIN lúc khởi động và tự cắt được, không
   cần binary ngoài nào. Phải chạy TRƯỚC `drop_privileges()`: sau khi bỏ root
   thì không còn quyền tạo namespace.
2. **`bwrap --unshare-net`** — máy phát triển và bộ test chạy không quyền, nơi
   `unshare` bị AppArmor chặn. `bwrap` đi qua `validate_executable`, nên nó
   không phải một lời gọi PATH tuỳ tiện.

Và nếu không đường nào dùng được: **FAIL CLOSED.** Không có "chạy tạm không
cách ly" — một mặc định thất bại theo hướng mở là một mặc định không tồn tại.
"""

from __future__ import annotations

import os

from shield.ai.worker.trusted import UntrustedExecutable, validate_executable

# Biến vỏ worker đọc để biết phải tự cắt mạng. Do supervisor đặt, không do cấu
# hình người dùng đặt.
NETNS_ENV = "SHIELD_WORKER_NETNS"

# Nơi `bwrap` được phép nằm. Tuyệt đối, không tra PATH.
BWRAP_CANDIDATES = ("/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap")


def unshare_network() -> dict:
    """Cắt mạng cho CHÍNH tiến trình này. -> mô tả kết quả, không ném.

    Người gọi quyết định fail-closed; hàm này chỉ báo cáo. Ba kết quả khác nhau
    — đã cắt, không có quyền, kernel không hỗ trợ — dẫn tới ba hành động khác
    nhau, nên gộp chúng thành một `False` là bỏ mất thông tin.
    """
    unshare = getattr(os, "unshare", None)
    clone_newnet = getattr(os, "CLONE_NEWNET", None)
    if unshare is None or clone_newnet is None:
        # `os.unshare` có từ Python 3.12; `requires-python` của dự án là 3.10.
        return {"isolated": False, "reason": "unshare_unavailable"}
    try:
        unshare(clone_newnet)
    except PermissionError:
        return {"isolated": False, "reason": "not_permitted"}
    except OSError as exc:
        return {"isolated": False, "reason": f"failed:{type(exc).__name__}"}
    return {"isolated": True, "mechanism": "unshare"}


def find_bwrap() -> str:
    """Đường dẫn `bwrap` đã qua chính sách tin cậy, hoặc rỗng."""
    for candidate in BWRAP_CANDIDATES:
        try:
            return str(validate_executable(candidate))
        except UntrustedExecutable:
            continue
    return ""


def sandbox_prefix() -> tuple[str, ...]:
    """argv chèn trước lệnh worker để cắt mạng từ BÊN NGOÀI. Rỗng nếu không có.

    Dùng khi agent chạy không quyền — `unshare` khi ấy bị từ chối, nhưng
    `bwrap` vẫn tạo được namespace. `--dev-bind / /` giữ nguyên hệ thống file:
    3C chỉ hứa cắt MẠNG, và hứa thêm thứ chưa kiểm được là nói dối trong tài
    liệu.
    """
    bwrap = find_bwrap()
    if not bwrap:
        return ()
    return (bwrap, "--unshare-net", "--dev-bind", "/", "/")


def plan(*, euid: int | None = None) -> dict:
    """Sẽ cắt mạng bằng cách nào. Quyết định ở PHÍA AGENT, trước khi sinh.

    Quyết định trước khi sinh chứ không giữa chừng: một worker đã chạy rồi mới
    phát hiện không cắt được mạng là một worker đã có mạng.
    """
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        # Root: worker tự cắt. Rẻ hơn, và không phụ thuộc binary ngoài nào.
        return {"mechanism": "unshare", "prefix": (), "worker_unshares": True}
    prefix = sandbox_prefix()
    if prefix:
        return {"mechanism": "bwrap", "prefix": prefix, "worker_unshares": False}
    return {"mechanism": "none", "prefix": (), "worker_unshares": False}
