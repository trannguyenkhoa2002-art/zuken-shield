"""Đọc log trên máy cài probe: journald, file log, và audit qua journald.

Hai yêu cầu chi phối toàn bộ thiết kế ở đây:

1. **Không mất dòng qua restart.** journald có con trỏ (`--cursor-file`), file
   log thì theo dõi bằng (inode, offset) — nếu chỉ nhớ offset, một lần
   logrotate là probe đọc lại từ đầu file mới hoặc bỏ qua cả file cũ.
2. **Không gửi trùng.** Con trỏ chỉ tiến sau khi dòng đã vào spool.

Cả hai đều lưu trong một file state JSON ghi nguyên tử.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("shield.probe.reader")

# Cùng bộ nhận diện mà collectors/local_log.py đang dùng để ra rule — probe
# gửi về đúng những dòng agent local sẽ hiểu, không nhiều hơn.
_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_SSH_ACCEPT = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")
_SUDO_FAIL = re.compile(r"(?P<user>\S+)\s*:\s*.*authentication failure|sudo:.*incorrect password")
_USB_ADD = re.compile(r"usb \S+: New USB device found.*idVendor=(?P<vendor>\w+).*idProduct=(?P<product>\w+)")


def classify(message: str, identifier: str) -> tuple[str, dict]:
    """Biến một dòng log thô thành (kind, fields).

    Phân loại ở PROBE chứ không ở server là có chủ ý: nó cắt được phần lớn
    lưu lượng ngay tại nguồn, và giữ đúng nguyên tắc "collector chỉ mô tả sự
    thật" — probe không quyết định gì là nguy hiểm, chỉ nói nó thấy gì.
    """
    match = _SSH_FAIL.search(message)
    if match:
        return "ssh_auth_failure", {"user": match.group("user"), "ip": match.group("ip")}
    match = _SSH_ACCEPT.search(message)
    if match:
        return "ssh_auth_success", {"user": match.group("user"), "ip": match.group("ip")}
    if _SUDO_FAIL.search(message):
        return "sudo_failure", {}
    match = _USB_ADD.search(message)
    if match:
        return "usb_device_added", {"vendor": match.group("vendor"), "product": match.group("product")}
    return "log_line", {"identifier": identifier}


class ReaderState:
    """State ghi nguyên tử — probe có thể bị giết bất cứ lúc nào."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.data: dict = {}
        self.load()

    def load(self) -> dict:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.data = raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            self.data = {}
        return self.data

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, self.path)


class FileLogReader:
    """Theo dõi một file log, chịu được logrotate.

    Khoá là (inode, offset). Chỉ nhớ offset thì sau logrotate probe sẽ nhảy
    vào giữa file mới (mất phần đầu) hoặc đọc lại từ đầu (gửi trùng cả file).
    """

    def __init__(self, path: Path, state: ReaderState) -> None:
        self.path = Path(path)
        self.state = state
        self.key = f"file:{self.path}"

    def _position(self) -> tuple[int | None, int, str]:
        saved = self.state.data.get(self.key) or {}
        return saved.get("inode"), int(saved.get("offset", 0)), str(saved.get("head", ""))

    HEAD_BYTES = 64

    def _head_signature(self, offset: int) -> str:
        """Vân tay của phần đầu file mà probe ĐÃ đọc qua.

        Chỉ so (inode, offset) là không đủ: `logrotate` chế độ `copytruncate`
        giữ nguyên inode, và nếu file mới tình cờ dài đúng bằng offset cũ thì
        `offset > size` không bắt được — probe sẽ im lặng bỏ qua toàn bộ nội
        dung mới.

        Vân tay lấy trên `min(64, offset)` byte ĐẦU chứ không phải 64 byte
        cố định: những byte đó probe đã đọc rồi nên chúng không được thay
        đổi. Nếu lấy cố định 64 byte, một file ngắn hơn 64 byte sẽ đổi vân
        tay mỗi lần có dòng mới, và probe tưởng lần nào cũng bị ghi đè.
        """
        limit = min(self.HEAD_BYTES, max(0, int(offset)))
        if limit == 0:
            return ""
        try:
            with self.path.open("rb") as handle:
                data = handle.read(limit)
        except OSError:
            return ""
        if len(data) < limit:
            return ""  # file ngắn đi rồi — nhánh cắt ngắn ở trên đã lo
        return hashlib.sha256(data).hexdigest()

    def read_new_lines(self, max_lines: int = 1000) -> list[str]:
        if not self.path.exists():
            return []
        stat = self.path.stat()
        inode, offset, head = self._position()
        current_head = self._head_signature(offset)

        if inode is not None and inode != stat.st_ino:
            # File đã bị xoay vòng: file cũ coi như hết, bắt đầu từ đầu file mới.
            logger.info("%s đã logrotate — đọc lại từ đầu file mới", self.path)
            offset = 0
        elif offset > stat.st_size:
            # File bị cắt ngắn tại chỗ (copytruncate).
            logger.info("%s bị cắt ngắn — đọc lại từ đầu", self.path)
            offset = 0
        elif head and current_head and head != current_head:
            # Cùng inode, cùng cỡ, nhưng nội dung đầu file đã khác -> đã bị
            # ghi đè. Đọc lại từ đầu, thà gửi trùng còn hơn mất trắng.
            logger.info("%s bị ghi đè tại chỗ — đọc lại từ đầu", self.path)
            offset = 0

        lines: list[str] = []
        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            for _ in range(max_lines):
                line = handle.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    # Dòng đang được ghi dở — để lần sau, đừng cắt đôi nó.
                    break
                lines.append(line.rstrip("\n"))
            new_offset = handle.tell()

        self.state.data[self.key] = {
            "inode": stat.st_ino, "offset": new_offset, "head": self._head_signature(new_offset),
        }
        return lines

    def commit(self) -> None:
        self.state.save()


class JournalReader:
    """Đọc journald bằng `journalctl --cursor-file` — systemd tự giữ con trỏ.

    `include_audit=True` đọc thêm bản ghi Linux Audit. Audit KHÔNG lọc theo
    `--identifier` được (nó tới qua `_TRANSPORT=audit`, không có
    SYSLOG_IDENTIFIER), nên phải là một lần gọi riêng với con trỏ riêng —
    dùng chung con trỏ sẽ khiến hai luồng nuốt mất bản ghi của nhau.
    """

    def __init__(self, state_dir: Path, identifiers: list[str], include_audit: bool = True) -> None:
        self.cursor_file = Path(state_dir) / "journal.cursor"
        self.audit_cursor_file = Path(state_dir) / "audit.cursor"
        self.identifiers = list(identifiers)
        self.include_audit = bool(include_audit)

    def command(self, max_lines: int) -> list[str]:
        command = [
            "/usr/bin/journalctl", "--output=json", "--no-pager",
            f"--lines={int(max_lines)}", f"--cursor-file={self.cursor_file}",
        ]
        for identifier in self.identifiers:
            command += ["--identifier", identifier]
        return command

    def audit_command(self, max_lines: int) -> list[str]:
        return [
            "/usr/bin/journalctl", "--output=json", "--no-pager",
            f"--lines={int(max_lines)}", f"--cursor-file={self.audit_cursor_file}",
            "_TRANSPORT=audit",
        ]

    def read_new_audit_records(self, max_lines: int = 500, timeout: float = 20.0) -> list[dict]:
        if not self.include_audit:
            return []
        return self._run(self.audit_command(max_lines), timeout)

    def read_new_records(self, max_lines: int = 500, timeout: float = 20.0) -> list[dict]:
        if not self.identifiers:
            # Danh sách rỗng = KHÔNG đọc journal, chứ không phải đọc tất cả.
            # `journalctl` không có --identifier nào sẽ trả về toàn bộ journal
            # của máy: vừa là quả bom khối lượng, vừa là chuyện gửi nguyên nhật
            # ký một máy người khác đi nơi khác mà chủ máy không hề chọn.
            return []
        return self._run(self.command(max_lines), timeout)

    def _run(self, command: list[str], timeout: float) -> list[dict]:
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(  # noqa: S603 - đường dẫn cố định, tham số dựng sẵn
                command, capture_output=True, text=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("journalctl không chạy được: %s", exc)
            return []
        if proc.returncode != 0:
            logger.warning("journalctl trả mã %d: %s", proc.returncode, proc.stderr.strip()[:200])
            return []

        records = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
        return records


def journal_record_to_event(record: dict, probe_id: str, hostname: str) -> dict:
    """Chuẩn hoá một bản ghi journald thành Event của Shield."""
    message = str(record.get("MESSAGE", ""))[:2000]
    identifier = str(record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or "")[:64]
    kind, fields = classify(message, identifier)
    try:
        ts = int(record.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000
    except (TypeError, ValueError):
        ts = 0.0
    return {
        "ts": ts or time.time(),
        "source": "probe.journal",
        "kind": kind,
        "data": {
            **fields,
            "message": message,
            "identifier": identifier,
            "unit": str(record.get("_SYSTEMD_UNIT", ""))[:128],
            "pid": str(record.get("_PID", ""))[:16],
            "probe_id": probe_id,
            "probe_host": hostname,
        },
    }


def file_line_to_event(line: str, path: Path, probe_id: str, hostname: str) -> dict:
    kind, fields = classify(line, path.name)
    return {
        "ts": time.time(),
        "source": "probe.file",
        "kind": kind,
        "data": {
            **fields,
            "message": line[:2000],
            "log_file": str(path),
            "probe_id": probe_id,
            "probe_host": hostname,
        },
    }


# Audit record đi qua journald dưới dạng chuỗi `key=value` trong MESSAGE.
_AUDIT_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
# execve trên i386 / x86_64 / aarch64 — cùng bộ mà collectors/auditd.py dùng.
_AUDIT_EXEC_SYSCALLS = {"11", "59", "221"}


def parse_audit_message(message: str) -> dict:
    fields = {}
    for key, value in _AUDIT_FIELD.findall(message[:4000]):
        fields[key] = value.strip('"')
    return fields


def audit_record_to_event(record: dict, probe_id: str, hostname: str) -> dict | None:
    """Chuẩn hoá một bản ghi audit. Trả None nếu không phải thứ ta quan tâm.

    Lọc ngay tại probe chứ không gửi tất cả: audit trên một máy bận sinh
    hàng nghìn dòng mỗi giây, và gửi hết về sẽ làm nghẹt event bus của Shield
    mà chẳng thêm thông tin gì.
    """
    message = str(record.get("MESSAGE", ""))
    fields = parse_audit_message(message)
    audit_type = str(record.get("_AUDIT_TYPE_NAME") or fields.get("type", ""))
    try:
        ts = int(record.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000
    except (TypeError, ValueError):
        ts = 0.0
    ts = ts or time.time()

    base = {
        "probe_id": probe_id, "probe_host": hostname,
        "audit_type": audit_type[:32],
        "uid": fields.get("uid", ""), "auid": fields.get("auid", ""),
    }

    if audit_type == "SYSCALL" and fields.get("syscall") in _AUDIT_EXEC_SYSCALLS:
        return {
            "ts": ts, "source": "probe.audit", "kind": "process_exec",
            "data": {**base, "exe": fields.get("exe", "")[:512],
                     "comm": fields.get("comm", "")[:128],
                     "success": fields.get("success", "")},
        }
    if audit_type in {"USER_AUTH", "USER_LOGIN", "USER_ACCT"}:
        kind = "ssh_auth_success" if fields.get("res") == "success" else "ssh_auth_failure"
        return {
            "ts": ts, "source": "probe.audit", "kind": kind,
            "data": {**base, "user": fields.get("acct", "")[:64],
                     "ip": fields.get("addr", "")[:64], "result": fields.get("res", "")},
        }
    if audit_type in {"CONFIG_CHANGE", "ANOM_ABEND", "AVC"}:
        return {
            "ts": ts, "source": "probe.audit", "kind": "log_line",
            "data": {**base, "message": message[:2000]},
        }
    return None
