"""Chụp hiện trạng hệ thống — action Level 1 (mục 4.3).

Đây là action ít nguy hiểm nhất và hữu ích nhất khi chạy TRƯỚC mọi thứ khác:
chặn xong thì hết dấu vết. Nó chỉ đọc và ghi ra một file trong thư mục của
Shield; không đổi trạng thái mạng, không đụng tiến trình nào.

Vẫn có `verify()` và `rollback()` đầy đủ, dù nghe như thừa với một hành động chỉ
đọc. Lý do: hợp đồng adapter chỉ có giá trị nếu KHÔNG có ngoại lệ. Một adapter
được miễn `verify()` vì "nó an toàn mà" là adapter đầu tiên trong một danh sách
sẽ dài ra.
"""

from __future__ import annotations

import os
from pathlib import Path

from shield.response.adapters.base import (
    ApplyResult,
    CheckResult,
    Impact,
    RollbackResult,
    VerificationResult,
)

# Chụp nhiều nhất bao nhiêu byte. Một `nft list ruleset` trên máy có hàng nghìn
# luật có thể rất lớn, và một action "an toàn" lấp đầy đĩa vẫn là một sự cố.
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MIN_FREE_BYTES = 256 * 1024 * 1024


class SnapshotAdapter:
    action = "snapshot_state"
    reversible = True
    human_only = False

    def __init__(self, snapshot_fn=None, snapshot_dir: Path | None = None) -> None:
        self.snapshot_fn = snapshot_fn
        self.snapshot_dir = snapshot_dir

    async def preview(self, plan: dict) -> Impact:
        return Impact(
            summary="Ghi lại bảng ARP, socket đang mở và toàn bộ ruleset firewall "
                    "vào một file trong thư mục của Shield. Không đổi gì trên hệ thống.",
            affected=({"service": "Đĩa", "target": str(self._dir())},),
            reversible=True, blast_radius="local-readonly",
        )

    def _dir(self) -> Path:
        if self.snapshot_dir is not None:
            return Path(self.snapshot_dir)
        from shield.agent.actions import default_snapshot_dir

        return default_snapshot_dir()

    async def check_preconditions(self, plan: dict) -> CheckResult:
        import shutil

        directory = self._dir()
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return CheckResult(False, ("disk_space_available",), str(exc),
                               reason_key="response.snapshot_err_no_dir",
                               reason_params={"error": str(exc)[:200]})
        try:
            if shutil.disk_usage(directory).free < MIN_FREE_BYTES:
                return CheckResult(False, ("disk_space_available",), "ổ đĩa sắp đầy",
                                   reason_key="response.snapshot_err_disk_full")
        except OSError:
            pass
        return CheckResult(True)

    async def apply(self, plan: dict, idempotency_key: str) -> ApplyResult:
        if self.snapshot_fn is None:
            from shield.agent import actions

            ok, path = await actions.snapshot_state()
        else:
            ok, path = await self.snapshot_fn()
        if not ok:
            return ApplyResult(False, str(path))
        return ApplyResult(True, str(path), rollback_token={"path": str(path)})

    async def verify(self, plan: dict, apply_result: ApplyResult) -> VerificationResult:
        """File có thật sự tồn tại và có nội dung không.

        "Lệnh chạy xong" không chứng minh file đã được ghi: đĩa đầy giữa chừng,
        thư mục bị xoá dưới chân, hay một lỗi ghi im lặng đều cho ra đúng cùng
        một exit code.
        """
        path = Path(str(apply_result.rollback_token.get("path") or ""))
        if not path.name:
            return VerificationResult(False, {}, "không biết file nào để kiểm",
                                      reason_key="response.snapshot_err_no_path")
        try:
            stat = path.stat()
        except OSError as exc:
            return VerificationResult(False, {"path": str(path)},
                                      f"file không tồn tại: {exc}",
                                      reason_key="response.snapshot_err_missing",
                                      reason_params={"path": str(path)})
        observed = {"path": str(path), "size": stat.st_size,
                    "mode": oct(stat.st_mode & 0o777)}
        if stat.st_size == 0:
            return VerificationResult(False, observed, "file rỗng",
                                      reason_key="response.snapshot_err_empty",
                                      reason_params={"path": str(path)})
        if stat.st_size > MAX_SNAPSHOT_BYTES:
            # Một action "an toàn" lấp đầy đĩa vẫn là một sự cố.
            return VerificationResult(False, observed, "file vượt trần dung lượng",
                                      reason_key="response.snapshot_err_too_big",
                                      reason_params={"path": str(path)})
        return VerificationResult(True, observed)

    async def rollback(self, plan: dict, apply_result: ApplyResult) -> RollbackResult:
        """Xoá file đã chụp. Xoá một file không tồn tại là thành công."""
        path = Path(str(apply_result.rollback_token.get("path") or ""))
        if not path.name:
            return RollbackResult(True, "không có file nào để xoá")
        try:
            os.unlink(path)
        except FileNotFoundError:
            return RollbackResult(True, "file đã không còn")
        except OSError as exc:
            return RollbackResult(False, str(exc))
        return RollbackResult(True, "đã xoá file chụp")
