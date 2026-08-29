"""Cách ly endpoint qua khung job bền vững (mục 4.2 và 4.3).

Đường cách ly đã đúng từ Batch 2.0-P0: áp nftables trong table riêng, đọc lại
ruleset từ kernel để kiểm chứng, chỉ arm dead-man sau khi kiểm chứng đạt. Cái
nó CHƯA có là máy trạng thái bền vững — nên agent chết giữa chừng chỉ được cứu
bởi một lượt đối chiếu riêng lúc khởi động, và không có lịch sử nào để đọc lại.

Adapter này đưa nó vào cùng khung với `block_ip`: mỗi lần cách ly là một job có
ID, có lịch sử chuyển trạng thái, có bằng chứng hậu kiểm lưu trên đĩa, và có
đường phục hồi chung với mọi action khác.

Mức Level 3 nên nó **luôn cần người duyệt** ở 2.0 (xem `decision/models.py`:
`MAX_AUTOMATIC_LEVEL` là Level 2). Đây không phải giới hạn tạm thời cho vui —
một máy tự cách ly mình vì một detector chưa hiệu chuẩn là một sự cố tự gây ra.
"""

from __future__ import annotations

from shield.response.adapters.base import (
    ApplyResult,
    CheckResult,
    Impact,
    RollbackResult,
    VerificationResult,
)
from shield.security.isolation import verify_isolation
from shield.security.response import ISOLATION_IMPACT, IsolationPlan


class IsolateEndpointAdapter:
    action = "isolate_endpoint"
    reversible = True
    # Level 3. Không bao giờ tự động ở 2.0.
    human_only = True

    def __init__(self, privileged_client, *, dead_man=None, nft_reader=None) -> None:
        self.privileged_client = privileged_client
        self.dead_man = dead_man
        self.nft_reader = nft_reader

    def _plan(self, plan: dict) -> IsolationPlan:
        return IsolationPlan.create(
            str(plan.get("management_ip", "")),
            int(plan.get("ttl_s", 300)),
            bool(plan.get("preserve_dns", False)),
        )

    async def preview(self, plan: dict) -> Impact:
        try:
            isolation = self._plan(plan)
        except (ValueError, TypeError) as exc:
            return Impact(summary=f"Kế hoạch cách ly không hợp lệ: {exc}",
                          reversible=True, blast_radius="whole-host")
        broken = [item for item in isolation.impact() if item["affected"]]
        return Impact(
            summary=(f"Cắt {', '.join(item['service'] for item in broken)} trong "
                     f"{isolation.ttl_s}s. Chỉ {isolation.management_ip} còn nối được. "
                     "Các kết nối đang mở bị cắt."),
            affected=tuple(dict(item) for item in ISOLATION_IMPACT),
            reversible=True, blast_radius="whole-host",
        )

    async def check_preconditions(self, plan: dict) -> CheckResult:
        try:
            self._plan(plan)
        except (ValueError, TypeError) as exc:
            return CheckResult(False, ("management_ip_known",), str(exc),
                               reason_key="response.isolate_err_bad_plan",
                               reason_params={"error": str(exc)[:200]})
        if self.dead_man is None:
            # Cách ly một máy rồi mất khả năng gỡ là hỏng nặng hơn thứ đang
            # phòng chống. Không có dead-man thì KHÔNG cách ly.
            return CheckResult(False, ("dead_man_switch_available",),
                               "chưa có dead-man switch để tự gỡ",
                               reason_key="response.isolate_err_no_deadman")
        if self.privileged_client is None:
            return CheckResult(False, ("privileged_helper_available",),
                               "không có privileged helper để áp luật firewall",
                               reason_key="response.isolate_err_no_helper")
        if self.nft_reader is None:
            # Không đọc lại được ruleset thì không kiểm chứng được, và không
            # kiểm chứng được thì không được áp: đó chính là lời nói dối cũ.
            return CheckResult(False, ("isolation_table_verified",),
                               "không có cách đọc lại ruleset để kiểm chứng",
                               reason_key="response.isolate_err_no_reader")
        return CheckResult(True)

    async def apply(self, plan: dict, idempotency_key: str) -> ApplyResult:
        isolation = self._plan(plan)
        try:
            response = await self.privileged_client.call("isolate_endpoint", {
                "management_ip": isolation.management_ip,
                "preserve_dns": isolation.preserve_dns,
            })
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            return ApplyResult(False, f"privileged helper: {exc}")
        if not response.get("ok"):
            return ApplyResult(False, str(response.get("message", "không rõ lý do")))
        return ApplyResult(True, str(response.get("message", "")), rollback_token={
            "management_ip": isolation.management_ip,
            "preserve_dns": isolation.preserve_dns,
            "ttl_s": isolation.ttl_s,
        })

    async def verify(self, plan: dict, apply_result: ApplyResult) -> VerificationResult:
        """Đọc lại table cách ly từ kernel.

        Helper cũng verify trước khi trả về, và lớp này verify lần nữa. Hai lần
        kiểm không thừa: helper kiểm ngay sau khi áp, còn lớp này kiểm ở thời
        điểm job chuyển sang VERIFYING — giữa hai mốc đó có thể có người xoá
        table, hoặc một lượt `nft flush ruleset` từ script khác.
        """
        management_ip = str(apply_result.rollback_token.get("management_ip")
                            or plan.get("management_ip", ""))
        preserve_dns = bool(apply_result.rollback_token.get("preserve_dns")
                            or plan.get("preserve_dns", False))
        try:
            raw = await self.nft_reader()
        except (OSError, RuntimeError) as exc:
            return VerificationResult(False, {}, f"không đọc được ruleset: {exc}",
                                      reason_key="response.verify_err_unreadable",
                                      reason_params={"error": str(exc)[:200]})
        ok, reason = verify_isolation(raw, management_ip, preserve_dns=preserve_dns)
        observed = {"management_ip": management_ip, "preserve_dns": preserve_dns,
                    "ruleset_bytes": len(raw or "")}
        if not ok:
            return VerificationResult(False, observed, reason,
                                      reason_key="response.isolate_err_not_verified",
                                      reason_params={"reason": reason[:200]})
        # CHỈ arm dead-man sau khi kiểm chứng đạt. Arm cho một lần cách ly chưa
        # từng xảy ra nghĩa là trạng thái trên đĩa nói dối về việc máy đang ở đâu.
        deadline = self.dead_man.arm(management_ip,
                                     int(apply_result.rollback_token.get("ttl_s") or 300))
        observed["dead_man_deadline"] = deadline
        return VerificationResult(True, observed, reason)

    async def rollback(self, plan: dict, apply_result: ApplyResult) -> RollbackResult:
        management_ip = str(apply_result.rollback_token.get("management_ip")
                            or plan.get("management_ip", ""))
        try:
            response = await self.privileged_client.call("release_isolation", {})
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            return RollbackResult(False, f"privileged helper: {exc}")
        if not response.get("ok"):
            # KHÔNG disarm khi gỡ hỏng: còn armed thì vòng dead-man còn thử lại.
            # Disarm ở đây nghĩa là không ai thử nữa và máy nằm ngoài mạng vĩnh viễn.
            return RollbackResult(False, str(response.get("message", "không rõ lý do")))
        if self.dead_man is not None and management_ip:
            self.dead_man.disarm(management_ip)
        return RollbackResult(True, "đã gỡ cách ly; mạng khôi phục")
