"""Hợp đồng chung của mọi response adapter (mục 4.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class Impact:
    """Cái gì sẽ đứt, nói bằng tên dịch vụ chứ không bằng số cổng.

    "deny non-management traffic" không nói cho ai biết rằng họ sắp mất cả SSH
    lẫn phân giải tên miền.
    """

    summary: str
    affected: tuple[dict, ...] = ()
    reversible: bool = True
    blast_radius: str = "unknown"

    def to_dict(self) -> dict:
        return {"summary": self.summary, "affected": [dict(a) for a in self.affected],
                "reversible": self.reversible, "blast_radius": self.blast_radius}


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    failed: tuple[str, ...] = ()
    detail: str = ""
    # Khoá dịch cho `detail`. Agent chạy ở một tiến trình khác và KHÔNG BIẾT
    # người đang nhìn màn hình chọn ngôn ngữ nào — chỉ giao diện biết. Đây là
    # lần thứ ba cùng một lỗi trong dự án này (thông báo lỗi xuất log, kết quả
    # phân tích, và giờ là lý do kiểm chứng), nên nó được đưa vào KIỂU dữ liệu
    # thay vì sửa từng chỗ.
    reason_key: str = ""
    reason_params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "failed": list(self.failed), "detail": self.detail,
                "reason_key": self.reason_key, "reason_params": dict(self.reason_params)}


@dataclass(frozen=True)
class ApplyResult:
    ok: bool
    detail: str = ""
    # Thứ cần để gỡ. Rỗng nghĩa là không gỡ được — và một adapter reversible
    # trả về rỗng là một lỗi, không phải một trường hợp bình thường.
    rollback_token: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "detail": self.detail,
                "rollback_token": dict(self.rollback_token)}


@dataclass(frozen=True)
class VerificationResult:
    """Kết quả đọc TRẠNG THÁI THẬT, không phải thông điệp của executor.

    `observed` rỗng nghĩa là không có kiểm chứng nào diễn ra. `verified=True`
    với `observed` rỗng là một lời nói dối — chính xác là lời nói dối Batch
    2.0-P0 tồn tại để chặn.
    """

    verified: bool
    observed: dict = field(default_factory=dict)
    reason: str = ""
    reason_key: str = ""
    reason_params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"verified": self.verified, "observed": dict(self.observed),
                "reason": self.reason, "reason_key": self.reason_key,
                "reason_params": dict(self.reason_params)}


@dataclass(frozen=True)
class RollbackResult:
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "detail": self.detail}


@runtime_checkable
class ResponseAdapter(Protocol):
    action: str
    reversible: bool
    human_only: bool

    async def preview(self, plan: dict) -> Impact: ...
    async def check_preconditions(self, plan: dict) -> CheckResult: ...
    async def apply(self, plan: dict, idempotency_key: str) -> ApplyResult: ...
    async def verify(self, plan: dict, apply_result: ApplyResult) -> VerificationResult: ...
    async def rollback(self, plan: dict, apply_result: ApplyResult) -> RollbackResult: ...
