"""Xuất log ra thư mục do người dùng chọn, có hạn mức người dùng đặt.

Vì sao tính năng này cần cẩn thận hơn vẻ ngoài của nó: agent chạy dưới **root**,
còn đường dẫn thì đến từ giao diện. Một tiến trình root ghi file vào chỗ do
người dùng chỉ định là công thức kinh điển của leo thang đặc quyền — chỉ cần
một symlink trong đường dẫn là root ghi đè được `/etc/shadow`.

Bốn lớp chặn, và không lớp nào thừa:

1. Đường dẫn phải TUYỆT ĐỐI và phải đã tồn tại. Shield không tự tạo thư mục
   sâu trong hệ thống file hộ ai.
2. Không thành phần nào trên đường dẫn được là symlink. Kiểm bằng `os.lstat`
   từng cấp, không phải bằng `resolve()` — `resolve()` đi theo symlink rồi trả
   về đích, tức là nó GIẤU đúng thứ cần phát hiện.
3. Thư mục đích không được nằm trong danh sách cấm (thư mục hệ thống), và cũng
   không được là thư mục dữ liệu của chính Shield.
4. Mọi lần mở file dùng `O_NOFOLLOW`: kể cả khi ai đó đặt symlink vào giữa hai
   lần kiểm, lần ghi vẫn hỏng thay vì ghi nhầm chỗ.

Hạn mức chỉ tính và chỉ xoá file DO SHIELD TẠO (khớp `shield-log-*.jsonl`).
Người dùng trỏ vào thư mục Documents của họ thì Shield không được đụng vào bất
cứ thứ gì khác trong đó.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("shield.log_export")

FILE_PREFIX = "shield-log-"
FILE_SUFFIX = ".jsonl"
ROTATE_BYTES = 16 * 1024 * 1024

# Hạn mức người dùng chọn được. Trần trên có chủ ý: một hạn mức "không giới
# hạn" nghĩa là Shield tự cho phép mình lấp đầy đĩa của người khác.
QUOTA_CHOICES_MB = (256, 512, 1024, 5 * 1024, 10 * 1024, 20 * 1024, 50 * 1024)
MIN_QUOTA_MB = 64
MAX_QUOTA_MB = 200 * 1024

# Chừa lại cho hệ thống. Hạn mức người dùng đặt là trần của Shield, không phải
# lời hứa rằng đĩa còn chỗ — nếu ổ sắp đầy thì dừng ghi là hành vi đúng, kể cả
# khi hạn mức chưa chạm.
MIN_FREE_BYTES = 512 * 1024 * 1024

# Thư mục không bao giờ được nhận log, dù người dùng có gõ tay vào ô nào.
FORBIDDEN_ROOTS = (
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root",
    "/run", "/sbin", "/sys", "/usr", "/var/lib", "/var/log", "/var/run",
)


class ExportPathError(ValueError):
    """Đường dẫn không dùng được.

    Mang một MÃ lỗi chứ không chỉ một câu tiếng Việt. Agent không biết người
    đang nhìn màn hình chọn ngôn ngữ nào — chỉ giao diện biết. Trả về câu đã
    viết sẵn nghĩa là người dùng tiếng Anh nhận được một câu tiếng Việt, và đó
    là lỗi đã xảy ra ở đúng chỗ này trong lần dựng đầu tiên.

    `detail` là phần không dịch được (đường dẫn cụ thể, thông báo của hệ điều
    hành) và được ghép vào sau câu đã dịch.
    """

    def __init__(self, code: str, detail: str = "", message: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(message or f"{code}{': ' + detail if detail else ''}")


@dataclass(frozen=True)
class ExportConfig:
    enabled: bool = False
    directory: str = ""
    max_bytes: int = 1024 * 1024 * 1024
    include_events: bool = True
    include_alerts: bool = True

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "directory": self.directory,
                "max_bytes": self.max_bytes, "include_events": self.include_events,
                "include_alerts": self.include_alerts}

    @classmethod
    def from_dict(cls, raw: dict) -> "ExportConfig":
        try:
            megabytes = int(raw.get("max_mb", 0)) or int(raw.get("max_bytes", 0)) // (1024 ** 2)
        except (TypeError, ValueError):
            megabytes = 1024
        megabytes = max(MIN_QUOTA_MB, min(megabytes or 1024, MAX_QUOTA_MB))
        return cls(
            enabled=bool(raw.get("enabled", False)),
            directory=str(raw.get("directory", "")),
            max_bytes=megabytes * 1024 ** 2,
            include_events=bool(raw.get("include_events", True)),
            include_alerts=bool(raw.get("include_alerts", True)),
        )


def validate_directory(raw_path: str, *, shield_data_dir: Path | None = None) -> Path:
    """Kiểm một đường dẫn do người dùng chọn. Ném ExportPathError kèm lý do.

    Lý do phải nói được cho người dùng, bằng tiếng người: một hộp thoại
    "đường dẫn không hợp lệ" không giúp ai sửa được gì.
    """
    text = str(raw_path or "").strip()
    if not text:
        raise ExportPathError("empty", message="chưa chọn thư mục")
    if "\x00" in text:
        raise ExportPathError("invalid_chars", message="đường dẫn chứa ký tự không hợp lệ")
    path = Path(text)
    if not path.is_absolute():
        raise ExportPathError("not_absolute", message="phải là đường dẫn tuyệt đối, bắt đầu bằng /")

    # Kiểm symlink theo TỪNG cấp bằng lstat. `Path.resolve()` đi theo symlink
    # rồi trả về đích — nó giấu đúng thứ ta cần phát hiện.
    walked = Path(path.anchor)
    for part in path.parts[1:]:
        walked = walked / part
        try:
            if os.path.islink(walked):
                raise ExportPathError("symlink", str(walked), f"đường dẫn đi qua liên kết tượng trưng: {walked}")
        except OSError as exc:
            raise ExportPathError("unreadable", f"{walked}: {exc}", f"không đọc được {walked}: {exc}") from exc

    # Kiểm BẢO MẬT trước kiểm tồn tại. Ngược lại thì `/etc/shield-logs` báo
    # "thư mục chưa tồn tại" — một lời mời tạo nó rồi thử lại, và thông báo
    # sai chỗ như vậy dạy người dùng đi đúng vào hướng nguy hiểm.
    normalised = os.path.normpath(str(path))
    for forbidden in FORBIDDEN_ROOTS:
        if normalised == forbidden:
            raise ExportPathError("system_dir", forbidden, f"không được ghi thẳng vào thư mục hệ thống {forbidden}")
        if forbidden != "/" and normalised.startswith(forbidden + "/"):
            raise ExportPathError("system_dir", forbidden, f"nằm trong thư mục hệ thống {forbidden}")

    data_dir = Path(shield_data_dir or "/var/lib/shield")
    if normalised == str(data_dir) or normalised.startswith(str(data_dir) + "/"):
        # Ghi log vào chính thư mục database nghĩa là hạn mức log ăn vào trần
        # dung lượng database, và hai cơ chế dọn dẹp sẽ giẫm lên nhau.
        raise ExportPathError("shield_data", message="không được trỏ vào thư mục dữ liệu của Shield")

    if not path.exists():
        raise ExportPathError("missing", message="thư mục chưa tồn tại — hãy tạo nó trước")
    if not path.is_dir():
        raise ExportPathError("not_a_directory", message="đường dẫn không phải là thư mục")

    if not os.access(path, os.W_OK):
        raise ExportPathError("not_writable", message="Shield không có quyền ghi vào thư mục này")
    return Path(normalised)


class LogExporter:
    """Ghi log ra thư mục người dùng chọn, tự xoay vòng và tự giữ hạn mức."""

    def __init__(self, config: ExportConfig, *, shield_data_dir: Path | None = None) -> None:
        self.config = config
        self.shield_data_dir = shield_data_dir
        self.directory: Path | None = None
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_detail = ""
        self.written_lines = 0
        self.dropped_lines = 0
        self._handle = None
        self._current: Path | None = None
        if config.enabled and config.directory:
            try:
                self.directory = validate_directory(config.directory,
                                                    shield_data_dir=shield_data_dir)
            except ExportPathError as exc:
                self.last_error = str(exc)
                self.last_error_code = exc.code
                self.last_error_detail = exc.detail
                logger.error("Xuất log bị tắt: %s", exc)

    # --- ghi ---

    def write(self, record: dict) -> bool:
        """Ghi một dòng JSONL. False nếu không ghi được (đã đếm vào dropped)."""
        if self.directory is None:
            return False
        try:
            payload = json.dumps(record, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            self.dropped_lines += 1
            self.last_error = f"không tuần tự hoá được bản ghi: {exc}"
            return False

        if not self._space_available(len(payload) + 1):
            self.dropped_lines += 1
            return False
        try:
            handle = self._open_current()
            handle.write(payload + "\n")
            handle.flush()
        except OSError as exc:
            self.dropped_lines += 1
            self.last_error = str(exc)
            self._close()
            return False
        self.written_lines += 1
        return True

    def _space_available(self, needed: int) -> bool:
        used = self.used_bytes()
        if used + needed > self.config.max_bytes:
            freed = self.enforce_quota(target=self.config.max_bytes - needed)
            if freed == 0 and used + needed > self.config.max_bytes:
                self.last_error = "đã chạm hạn mức và không còn file cũ để xoá"
                return False
        try:
            if shutil.disk_usage(self.directory).free < MIN_FREE_BYTES:
                # Hạn mức là trần của Shield, không phải lời hứa còn chỗ trống.
                self.last_error = "ổ đĩa sắp đầy — tạm dừng ghi log"
                return False
        except OSError:
            pass
        return True

    def _open_current(self):
        if self._handle is not None and self._current is not None:
            try:
                if self._current.stat().st_size < ROTATE_BYTES:
                    return self._handle
            except OSError:
                pass
            self._close()
        assert self.directory is not None
        self._current = self.directory / f"{FILE_PREFIX}{int(time.time())}{FILE_SUFFIX}"
        # O_NOFOLLOW: kể cả khi ai đó đặt symlink vào giữa hai lần kiểm, lần
        # ghi này hỏng thay vì ghi nhầm chỗ. Agent chạy root nên "ghi nhầm chỗ"
        # có thể nghĩa là ghi đè một file hệ thống.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
        descriptor = os.open(self._current, flags, 0o640)
        self._handle = os.fdopen(descriptor, "a", encoding="utf-8")
        return self._handle

    def _close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
        self._handle, self._current = None, None

    def close(self) -> None:
        self._close()

    # --- hạn mức ---

    def _own_files(self) -> list[Path]:
        """Chỉ file DO SHIELD TẠO. Người dùng trỏ vào thư mục Documents của họ
        thì Shield không được đụng vào bất cứ thứ gì khác trong đó."""
        if self.directory is None:
            return []
        try:
            return sorted(
                (p for p in self.directory.iterdir()
                 if p.is_file() and not p.is_symlink()
                 and p.name.startswith(FILE_PREFIX) and p.name.endswith(FILE_SUFFIX)),
                key=lambda p: p.name,
            )
        except OSError as exc:
            self.last_error = str(exc)
            return []

    def used_bytes(self) -> int:
        total = 0
        for path in self._own_files():
            try:
                total += path.stat().st_size
            except OSError:
                continue
        return total

    def enforce_quota(self, target: int | None = None) -> int:
        """Xoá file CŨ NHẤT cho tới khi về dưới hạn mức. Trả về số byte đã giải phóng."""
        limit = self.config.max_bytes if target is None else max(0, target)
        files = self._own_files()
        used = self.used_bytes()
        freed = 0
        for path in files:
            if used <= limit:
                break
            if path == self._current:
                # Không xoá file đang mở: ghi tiếp vào một inode đã bị gỡ tên
                # nghĩa là dữ liệu biến mất trong im lặng.
                continue
            try:
                size = path.stat().st_size
                path.unlink()
            except OSError:
                continue
            used -= size
            freed += size
        if freed:
            logger.info("Xuất log: giải phóng %.1f MB để giữ hạn mức", freed / 1024 ** 2)
        return freed

    # --- thông tin cho người dùng ---

    def stats(self, *, rate_lines_per_s: float = 0.0, average_line_bytes: int = 0) -> dict:
        """Mọi con số người dùng cần để quyết định hạn mức bao nhiêu là đủ."""
        files = self._own_files()
        used = self.used_bytes()
        free = 0
        if self.directory is not None:
            try:
                free = shutil.disk_usage(self.directory).free
            except OSError:
                free = 0
        per_day = rate_lines_per_s * 86400 * max(1, average_line_bytes or 220)
        return {
            "enabled": bool(self.config.enabled),
            "active": self.directory is not None,
            "directory": str(self.directory) if self.directory else self.config.directory,
            "max_bytes": self.config.max_bytes,
            "used_bytes": used,
            "used_percent": round(100 * used / self.config.max_bytes, 1) if self.config.max_bytes else 0.0,
            "file_count": len(files),
            "oldest_file": files[0].name if files else "",
            "newest_file": files[-1].name if files else "",
            "disk_free_bytes": free,
            "written_lines": self.written_lines,
            "dropped_lines": self.dropped_lines,
            "bytes_per_day_estimate": int(per_day),
            # Ước tính giữ được bao nhiêu ngày. Đây là con số người dùng thật
            # sự muốn biết khi chọn hạn mức — "10 GB" không nói gì, "khoảng 12
            # ngày" thì nói rất nhiều.
            "days_retained_estimate": round(self.config.max_bytes / per_day, 1) if per_day > 0 else None,
            "last_error": self.last_error,
            "last_error_code": self.last_error_code,
            "last_error_detail": self.last_error_detail,
        }
