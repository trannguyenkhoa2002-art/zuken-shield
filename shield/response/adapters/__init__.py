"""Adapter cho từng action (KE-HOACH-SHIELD-2.0.md mục 4.2).

Mọi adapter phải cung cấp đủ năm phương thức:

    preview(plan)                 -> Impact
    check_preconditions(plan)     -> CheckResult
    apply(plan, idempotency_key)  -> ApplyResult
    verify(plan, apply_result)    -> VerificationResult
    rollback(plan, apply_result)  -> RollbackResult

Không thêm action mới nếu thiếu `verify()` và `rollback()`. Ngoại lệ duy nhất là
action phá huỷ ở Level 4: nó phải khai tường minh `reversible=False` và luôn
`human_only`, và có test đọc AST khẳng định không adapter nào lách được điều đó.
"""

from shield.response.adapters.base import (
    ApplyResult,
    CheckResult,
    Impact,
    ResponseAdapter,
    RollbackResult,
    VerificationResult,
)

__all__ = ["ApplyResult", "CheckResult", "Impact", "ResponseAdapter",
           "RollbackResult", "VerificationResult"]
