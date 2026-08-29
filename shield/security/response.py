"""Reversible endpoint response primitives and two-step execution gate."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import shutil
import signal
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from shield.common.models import Event


@dataclass(frozen=True)
class ResponseResult:
    ok: bool
    action: str
    target: str
    message: str
    rollback_id: str | None = None


def default_quarantine_root() -> Path:
    configured = os.environ.get("SHIELD_QUARANTINE_DIR")
    if configured:
        return Path(configured)
    production = Path("/var/lib/shield/quarantine")
    if production.parent.exists() and os.access(production.parent, os.W_OK):
        return production
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "shield" / "quarantine"


def process_start_ticks(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    if pid <= 1:
        return None
    try:
        stat = (proc_root / str(pid) / "stat").read_text(errors="replace")
        end = stat.rfind(")")
        return stat[end + 2 :].split()[19]
    except (FileNotFoundError, PermissionError, OSError, IndexError):
        return None


def stop_process(pid: int, expected_start_ticks: str, *, dry_run: bool = True, proc_root: Path = Path("/proc")) -> ResponseResult:
    actual = process_start_ticks(pid, proc_root)
    target = f"pid:{pid}"
    if actual is None:
        return ResponseResult(False, "stop_process", target, "process not found or protected")
    if not expected_start_ticks or actual != str(expected_start_ticks):
        return ResponseResult(False, "stop_process", target, "PID identity changed; refusing")
    if dry_run:
        return ResponseResult(True, "stop_process", target, "dry-run: would send SIGTERM")
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError) as exc:
        return ResponseResult(False, "stop_process", target, str(exc))
    return ResponseResult(True, "stop_process", target, "SIGTERM sent")


def process_tree_identities(root_pid: int, expected_start_ticks: str, proc_root: Path = Path("/proc")) -> list[dict]:
    """Snapshot descendants with PID start ticks, children first.

    Identity is revalidated again by stop_process before any signal, closing the
    PID-reuse race between preview and execution.
    """
    if process_start_ticks(root_pid, proc_root) != str(expected_start_ticks):
        return []
    parents, ticks = {}, {}
    for item in proc_root.iterdir():
        if not item.name.isdigit() or int(item.name) <= 1:
            continue
        try:
            stat = (item / "stat").read_text(errors="replace")
            end = stat.rfind(")")
            fields = stat[end + 2:].split()
            parents[int(item.name)] = int(fields[1])
            ticks[int(item.name)] = fields[19]
        except (OSError, ValueError, IndexError):
            continue
    depth = {root_pid: 0}
    changed = True
    while changed:
        changed = False
        for pid, ppid in parents.items():
            if ppid in depth and pid not in depth:
                depth[pid] = depth[ppid] + 1
                changed = True
    return [{"pid": pid, "start_ticks": ticks.get(pid, ""), "depth": level}
            for pid, level in sorted(depth.items(), key=lambda item: item[1], reverse=True)
            if ticks.get(pid)]


# Dịch vụ mà việc cách ly sẽ cắt đứt. Liệt kê tường minh vì người bấm nút cần
# biết CỤ THỂ cái gì sẽ hỏng — "deny non-management traffic" không nói cho ai
# biết rằng họ sắp mất cả SSH lẫn phân giải tên miền.
ISOLATION_IMPACT = (
    {"service": "SSH", "ports": [22], "impact": "Mọi phiên SSH tới máy này sẽ đứt, trừ từ địa chỉ quản trị"},
    {"service": "DNS", "ports": [53], "impact": "Máy không phân giải được tên miền — mọi thứ dựa vào tên miền đều hỏng"},
    {"service": "Web", "ports": [80, 443], "impact": "Không truy cập được web, không tải được bản cập nhật"},
    {"service": "Chia sẻ file", "ports": [139, 445, 2049], "impact": "Ổ đĩa mạng và thư mục chia sẻ ngắt kết nối"},
    {"service": "Email", "ports": [25, 143, 465, 587, 993], "impact": "Ứng dụng mail mất kết nối tới máy chủ"},
)


@dataclass(frozen=True)
class IsolationPlan:
    management_ip: str
    ttl_s: int
    preserve_dns: bool = False

    @classmethod
    def create(cls, management_ip: str, ttl_s: int = 300, preserve_dns: bool = False):
        import ipaddress
        address = ipaddress.ip_address(management_ip)
        if address.is_unspecified or address.is_multicast or not 30 <= int(ttl_s) <= 3600:
            raise ValueError("unsafe endpoint isolation plan")
        return cls(str(address), int(ttl_s), bool(preserve_dns))

    def impact(self) -> list[dict]:
        """Cái gì sẽ đứt, nói bằng tên dịch vụ chứ không bằng số cổng."""
        items = []
        for entry in ISOLATION_IMPACT:
            if self.preserve_dns and entry["service"] == "DNS":
                items.append({**entry, "affected": False,
                              "impact": "Giữ nguyên DNS theo yêu cầu"})
            else:
                items.append({**entry, "affected": True})
        return items

    def preview(self) -> ResponseResult:
        broken = [item["service"] for item in self.impact() if item["affected"]]
        return ResponseResult(
            True, "isolate_endpoint", self.management_ip,
            f"dry-run: sẽ cắt {', '.join(broken)} trong {self.ttl_s}s; "
            f"chỉ {self.management_ip} còn nối được. Tự gỡ khi hết hạn.",
            rollback_id=None,
        )


MAX_DEADMAN_TTL_S = 24 * 3600


class DeadManSwitch:
    """Tự gỡ cách ly nếu agent ngừng gia hạn.

    Đây là phần khiến việc cách ly an toàn để dùng thật. Không có nó, kịch bản
    tệ nhất là: agent cách ly máy rồi chính agent chết (crash, OOM, bị giết) —
    và máy nằm ngoài mạng vĩnh viễn, không ai vào sửa được, kể cả qua SSH.
    Chỉ còn cách tới tận nơi cắm màn hình.

    Cơ chế: mỗi lần cách ly đặt một hạn chót. Agent phải gọi `renew()` trước
    hạn. Quá hạn mà không gia hạn -> `expired()` trả True và caller PHẢI gỡ.
    Trạng thái ghi ra đĩa, nên agent khởi động lại vẫn biết mình đang nợ một
    lần gỡ.
    """

    def __init__(self, state_path: Path, clock=time.time) -> None:
        self.state_path = Path(state_path)
        # Đồng hồ TƯỜNG, không phải monotonic: hạn chót được ghi ra đĩa và đọc
        # lại ở một tiến trình khác, mà monotonic chỉ có nghĩa trong đúng một
        # tiến trình — ghi ra rồi so ở tiến trình sau là so hai thang đo khác
        # nhau, và sau khi máy khởi động lại thì sai hoàn toàn.
        #
        # Đồng hồ tường có thể bị NTP kéo giật. Với dead-man, gỡ sớm là phiền,
        # gỡ không bao giờ là hỏng — nên chọn cái phiền.
        self._clock = clock
        self._deadlines: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        """Đọc lại hạn chót đang nợ. Không có bước này thì cả lớp vô nghĩa:
        agent khởi động lại sẽ quên mất nó đang cách ly ai, không ai gỡ luật
        nữa, và máy nằm ngoài mạng vĩnh viễn — đúng thảm hoạ lớp này sinh ra
        để chặn."""
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        ceiling = self._clock() + MAX_DEADMAN_TTL_S
        for target, deadline in raw.items():
            try:
                value = float(deadline)
            except (TypeError, ValueError):
                continue
            # Chặn trần: một file trạng thái hỏng (hoặc bị sửa) với hạn chót
            # năm 2099 sẽ ghim cách ly vĩnh viễn.
            self._deadlines[str(target)] = min(value, ceiling)

    def arm(self, target: str, ttl_s: float) -> float:
        deadline = self._clock() + min(MAX_DEADMAN_TTL_S, max(1.0, float(ttl_s)))
        self._deadlines[target] = deadline
        self._persist()
        return deadline

    def renew(self, target: str, ttl_s: float) -> bool:
        if target not in self._deadlines:
            return False
        self._deadlines[target] = self._clock() + min(MAX_DEADMAN_TTL_S, max(1.0, float(ttl_s)))
        self._persist()
        return True

    def disarm(self, target: str) -> bool:
        removed = self._deadlines.pop(target, None) is not None
        if removed:
            self._persist()
        return removed

    def expired(self) -> list[str]:
        at = self._clock()
        return sorted(target for target, deadline in self._deadlines.items() if at >= deadline)

    def armed(self) -> dict[str, float]:
        return dict(self._deadlines)

    def _persist(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.state_path.with_suffix(".tmp")
            temp.write_text(json.dumps(self._deadlines, sort_keys=True), encoding="utf-8")
            os.replace(temp, self.state_path)
        except OSError:
            # Ghi hỏng không được làm hỏng việc cách ly đang diễn ra; trạng
            # thái trong bộ nhớ vẫn đủ để gỡ trong phiên hiện tại.
            pass


class Quarantine:
    def __init__(self, root: Path, max_bytes: int = 512 * 1024 * 1024) -> None:
        self.root = root.resolve()
        self.max_bytes = max_bytes
        self.files = self.root / "files"
        self.manifests = self.root / "manifests"

    def quarantine(self, source: Path, *, dry_run: bool = True) -> ResponseResult:
        if source.is_symlink():
            return ResponseResult(False, "quarantine_file", str(source), "symlink targets are not allowed")
        source = source.resolve(strict=True)
        if not source.is_file():
            return ResponseResult(False, "quarantine_file", str(source), "target must be a regular file")
        stat = source.stat()
        if stat.st_size > self.max_bytes:
            return ResponseResult(False, "quarantine_file", str(source), "file exceeds quarantine limit")
        hasher = hashlib.sha256()
        with source.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        if dry_run:
            return ResponseResult(True, "quarantine_file", str(source), f"dry-run: sha256={digest}")
        item_id = uuid.uuid4().hex
        self.files.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.manifests.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination = self.files / item_id
        temporary = self.files / f".{item_id}.tmp"
        try:
            with source.open("rb") as source_handle, temporary.open("xb") as target_handle:
                shutil.copyfileobj(source_handle, target_handle, 1024 * 1024)
                target_handle.flush()
                os.fsync(target_handle.fileno())
            temporary.chmod(0o600)
            copied_hash = hashlib.sha256()
            with temporary.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    copied_hash.update(chunk)
            current = source.stat()
            if copied_hash.hexdigest() != digest or (current.st_dev, current.st_ino, current.st_size) != (stat.st_dev, stat.st_ino, stat.st_size):
                temporary.unlink(missing_ok=True)
                return ResponseResult(False, "quarantine_file", str(source), "source changed during quarantine")
            os.replace(temporary, destination)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)
            return ResponseResult(False, "quarantine_file", str(source), str(exc))
        manifest = {
            "id": item_id, "original_path": str(source), "quarantined_path": str(destination),
            "sha256": digest, "size": stat.st_size, "mode": stat.st_mode & 0o777,
            "quarantined_ts": time.time(),
        }
        manifest_path = self.manifests / f"{item_id}.json"
        manifest_temp = self.manifests / f".{item_id}.tmp"
        try:
            manifest_temp.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
            manifest_temp.chmod(0o600)
            os.replace(manifest_temp, manifest_path)
            source.unlink()
        except OSError as exc:
            manifest_temp.unlink(missing_ok=True)
            manifest_path.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)
            return ResponseResult(False, "quarantine_file", str(source), str(exc))
        return ResponseResult(True, "quarantine_file", str(source), "file quarantined", item_id)

    def restore(self, item_id: str, *, dry_run: bool = True) -> ResponseResult:
        if not item_id or any(c not in "0123456789abcdef" for c in item_id):
            return ResponseResult(False, "restore_quarantine", item_id, "invalid rollback id")
        manifest_path = self.manifests / f"{item_id}.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            source = Path(manifest["quarantined_path"])
            destination = Path(manifest["original_path"])
        except (FileNotFoundError, KeyError, ValueError, OSError):
            return ResponseResult(False, "restore_quarantine", item_id, "manifest not found or invalid")
        if destination.exists() or not destination.parent.exists():
            return ResponseResult(False, "restore_quarantine", str(destination), "restore destination is unsafe")
        if dry_run:
            return ResponseResult(True, "restore_quarantine", str(destination), "dry-run: would restore", item_id)
        os.replace(source, destination)
        destination.chmod(int(manifest["mode"]))
        manifest_path.unlink()
        return ResponseResult(True, "restore_quarantine", str(destination), "file restored", item_id)


class ResponseExecutor:
    """Two-step gate: preview issues a single-use, expiring approval token."""

    def __init__(self, quarantine: Quarantine, token_ttl_s: float = 60.0, privileged_client=None,
                 dead_man: "DeadManSwitch | None" = None, event_sink=None) -> None:
        # `event_sink` nhận event khi một response KHÔNG vượt qua kiểm chứng.
        # Không có nó thì thất bại chỉ nằm trong giá trị trả về, và giá trị trả
        # về thì đi vào một hộp thoại rồi biến mất — không detector nào thấy,
        # không alert nào bật, không ai biết Shield vừa hứa một việc nó không
        # làm được.
        self.event_sink = event_sink
        self.dead_man = dead_man
        self.quarantine = quarantine
        self.token_ttl_s = token_ttl_s
        self.privileged_client = privileged_client
        self._tokens: dict[str, tuple[float, str, str, str]] = {}

    def _report_verification_failure(self, action: str, target: str, reason: str) -> None:
        """Phát một event để pipeline detection nhìn thấy thất bại này.

        Đây là mắt xích corpus ground-truth bắt được: không detector nào phản
        ứng khi một response thất bại kiểm chứng, nên một hành động báo thành
        công rồi hoá ra không đổi trạng thái hệ thống sẽ trôi qua trong im lặng.
        """
        if self.event_sink is None:
            return
        try:
            self.event_sink(Event(time.time(), "response", "response_verification_failed", {
                "action": action, "target": target, "reason": reason[:500],
            }))
        except Exception:  # noqa: BLE001 — báo cáo thất bại không được che mất thất bại
            pass

    @staticmethod
    def _fingerprint(params: dict) -> str:
        return hashlib.sha256(json.dumps(params, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    async def preview(self, action: str, params: dict, owner: str = "") -> tuple[str | None, ResponseResult]:
        result = await self._dispatch(action, params, dry_run=True)
        if not result.ok:
            return None, result
        token = secrets.token_urlsafe(24)
        self._tokens[token] = (time.monotonic() + self.token_ttl_s, action, self._fingerprint(params), owner)
        return token, result

    async def execute(self, token: str, action: str, params: dict, owner: str = "") -> ResponseResult:
        record = self._tokens.pop(token, None)
        if record is None or record[0] < time.monotonic():
            return ResponseResult(False, action, "", "approval token missing or expired")
        if record[1:] != (action, self._fingerprint(params), owner):
            return ResponseResult(False, action, "", "approval token does not match request")
        return await self._dispatch(action, params, dry_run=False)

    async def _dispatch(self, action: str, params: dict, *, dry_run: bool) -> ResponseResult:
        if action == "stop_process":
            if not dry_run and self.privileged_client is not None:
                try:
                    response = await self.privileged_client.call("stop_process", {
                        "pid": int(params.get("pid", 0)), "start_ticks": str(params.get("start_ticks", "")),
                    })
                    return ResponseResult(bool(response.get("ok")), action, f"pid:{params.get('pid')}", response.get("message", ""))
                except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                    return ResponseResult(False, action, f"pid:{params.get('pid')}", f"privileged helper: {exc}")
            return await asyncio.to_thread(stop_process, int(params.get("pid", 0)), str(params.get("start_ticks", "")), dry_run=dry_run)
        if action == "stop_process_tree":
            pid, ticks = int(params.get("pid", 0)), str(params.get("start_ticks", ""))
            identities = await asyncio.to_thread(process_tree_identities, pid, ticks)
            if not identities:
                return ResponseResult(False, action, f"pid:{pid}", "process tree identity changed or unavailable")
            if dry_run:
                return ResponseResult(True, action, f"pid:{pid}", f"dry-run: would stop {len(identities)} identity-checked processes")
            failures = []
            for identity in identities:
                if self.privileged_client is not None:
                    response = await self.privileged_client.call("stop_process", {
                        "pid": identity["pid"], "start_ticks": identity["start_ticks"],
                    })
                    if not response.get("ok"):
                        failures.append(identity["pid"])
                else:
                    result = await asyncio.to_thread(stop_process, identity["pid"], identity["start_ticks"], dry_run=False)
                    if not result.ok:
                        failures.append(identity["pid"])
            return ResponseResult(not failures, action, f"pid:{pid}",
                                  f"stopped {len(identities) - len(failures)}/{len(identities)} processes")
        if action == "isolate_endpoint":
            try:
                plan = IsolationPlan.create(str(params.get("management_ip", "")), int(params.get("ttl_s", 300)), bool(params.get("preserve_dns", False)))
            except (ValueError, TypeError):
                return ResponseResult(False, action, "", "invalid isolation plan")
            if dry_run:
                return plan.preview()
            if self.dead_man is None:
                # Không có công tắc tự gỡ thì KHÔNG cách ly. Cách ly một máy
                # rồi mất khả năng gỡ là hỏng nặng hơn thứ đang phòng chống.
                return ResponseResult(False, action, plan.management_ip,
                                      "cách ly bị chặn: chưa có dead-man switch để tự gỡ")
            if self.privileged_client is None:
                # Không có helper thì không có cách nào áp luật firewall. Bản
                # trước vẫn trả ok=True ở đúng đây: arm dead-man rồi báo "đã
                # cách ly" trong khi máy nối mạng bình thường. Người vận hành
                # tin là đã cô lập được máy nên ngừng tìm cách khác — dạng
                # hỏng nguy hiểm nhất một sản phẩm phòng thủ có thể có.
                return ResponseResult(False, action, plan.management_ip,
                                      "cách ly bị chặn: không có privileged helper để áp luật firewall")
            try:
                response = await self.privileged_client.call("isolate_endpoint", {
                    "management_ip": plan.management_ip, "preserve_dns": plan.preserve_dns,
                })
            except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                return ResponseResult(False, action, plan.management_ip, f"privileged helper: {exc}")
            if not response.get("ok"):
                # Chưa cách ly được thì KHÔNG arm dead-man. Arm cho một lần
                # cách ly chưa từng xảy ra nghĩa là mỗi lần agent khởi động lại
                # đều cố gỡ một thứ không tồn tại, và trạng thái trên đĩa nói
                # dối về việc máy đang ở đâu.
                self._report_verification_failure(
                    action, plan.management_ip, str(response.get("message", "không rõ lý do")))
                return ResponseResult(False, action, plan.management_ip,
                                      f"cách ly thất bại: {response.get('message', 'không rõ lý do')}")
            # Tới đây helper đã áp luật VÀ đọc lại ruleset từ kernel để kiểm
            # chứng. Bây giờ mới arm đồng hồ tự gỡ.
            deadline = self.dead_man.arm(plan.management_ip, plan.ttl_s)
            return ResponseResult(
                True, action, plan.management_ip,
                f"đã cách ly và kiểm chứng; tự gỡ sau {plan.ttl_s}s nếu agent không gia hạn",
                rollback_id=f"isolation:{plan.management_ip}:{deadline:.0f}",
            )
        if action == "release_isolation":
            target = str(params.get("management_ip", ""))
            if dry_run:
                return ResponseResult(True, action, target, "dry-run: sẽ xoá table cách ly và khôi phục mạng")
            if self.privileged_client is None:
                return ResponseResult(False, action, target,
                                      "không có privileged helper để gỡ luật firewall")
            try:
                response = await self.privileged_client.call("release_isolation", {})
            except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                return ResponseResult(False, action, target, f"privileged helper: {exc}")
            if not response.get("ok"):
                # Giữ nguyên hạn chót: còn armed thì vòng dead-man còn thử gỡ
                # lại. Disarm ở đây nghĩa là không ai thử nữa.
                return ResponseResult(False, action, target,
                                      f"gỡ cách ly thất bại: {response.get('message', 'không rõ lý do')}")
            if self.dead_man is not None and target:
                self.dead_man.disarm(target)
            return ResponseResult(True, action, target, "đã gỡ cách ly; mạng khôi phục")
        if action == "quarantine_file":
            try:
                return await asyncio.to_thread(self.quarantine.quarantine, Path(str(params.get("path", ""))), dry_run=dry_run)
            except (FileNotFoundError, PermissionError, OSError) as exc:
                return ResponseResult(False, action, str(params.get("path", "")), str(exc))
        if action == "restore_quarantine":
            return await asyncio.to_thread(self.quarantine.restore, str(params.get("rollback_id", "")), dry_run=dry_run)
        return ResponseResult(False, action, "", "action is not allowlisted")
