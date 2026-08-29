"""Giới hạn tốc độ tạm thời — action Level 2 (mục 4.3).

Bậc thang giữa "không làm gì" và "chặn hẳn". Một địa chỉ đang quét cổng bị làm
chậm tới mức vô dụng, nhưng nếu Shield đoán sai thì người dùng thật ở địa chỉ đó
vẫn làm việc được — chậm, chứ không đứt. Đó là lý do action này đáng tồn tại
riêng thay vì để `block_ip` gánh mọi trường hợp: hậu quả của một lần đoán sai
thấp hơn hẳn, nên ngưỡng để dùng nó cũng thấp hơn.

Dùng lại đúng danh sách địa chỉ được bảo vệ của `block_ip`: làm chậm gateway
hay DNS resolver không phá mạng như chặn hẳn, nhưng nó biến mọi thứ thành
"lúc được lúc không" — dạng hỏng khó chẩn đoán hơn cả đứt hẳn.
"""

from __future__ import annotations

import json

from shield.response.adapters.base import (
    ApplyResult,
    CheckResult,
    Impact,
    RollbackResult,
    VerificationResult,
)
from shield.response.adapters.temporary_block import protected_reason_key


class RateLimitAdapter:
    action = "rate_limit_ip"
    reversible = True
    human_only = False

    def __init__(self, privileged_client, *, gateway: str = "", resolvers=(),
                 management: str = "", nft_reader=None) -> None:
        self.privileged_client = privileged_client
        self.gateway = gateway
        self.resolvers = tuple(resolvers)
        self.management = management
        self.nft_reader = nft_reader

    async def preview(self, plan: dict) -> Impact:
        from shield.agent.actions import RATE_LIMIT

        ip = str(plan.get("ip", ""))
        return Impact(
            summary=(f"Giới hạn lưu lượng từ {ip} xuống {RATE_LIMIT} trong "
                     f"{int(plan.get('ttl_s', 0))} giây. Kết nối không đứt, chỉ chậm."),
            affected=({"service": "Tốc độ kết nối từ địa chỉ này", "target": ip},),
            reversible=True, blast_radius="single-peer",
        )

    async def check_preconditions(self, plan: dict) -> CheckResult:
        ip = str(plan.get("ip", ""))
        key, reason = protected_reason_key(ip, gateway=self.gateway,
                                           resolvers=self.resolvers,
                                           management=self.management)
        if reason:
            return CheckResult(False, ("target_not_in_protected_allowlist",), reason,
                               reason_key=key, reason_params={"ip": ip})
        if int(plan.get("ttl_s", 0)) <= 0:
            return CheckResult(False, ("ttl_within_limit",),
                               "giới hạn tốc độ phải có thời hạn",
                               reason_key="response.block_err_no_ttl")
        if self.privileged_client is None:
            return CheckResult(False, ("privileged_helper_available",),
                               "không có privileged helper để áp luật",
                               reason_key="response.block_err_no_helper")
        return CheckResult(True)

    async def apply(self, plan: dict, idempotency_key: str) -> ApplyResult:
        ip = str(plan.get("ip", ""))
        try:
            response = await self.privileged_client.call("rate_limit_ip", {"ip": ip})
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            return ApplyResult(False, f"privileged helper: {exc}")
        if not response.get("ok"):
            return ApplyResult(False, str(response.get("message", "không rõ lý do")))
        return ApplyResult(True, "đã thêm vào set ratelimited_ips",
                           rollback_token={"ip": ip, "idempotency_key": idempotency_key})

    async def verify(self, plan: dict, apply_result: ApplyResult) -> VerificationResult:
        ip = str(plan.get("ip", ""))
        if self.nft_reader is None:
            return VerificationResult(False, {}, "không có cách đọc ruleset để kiểm chứng",
                                      reason_key="response.verify_err_no_reader")
        try:
            raw = await self.nft_reader()
        except (OSError, RuntimeError) as exc:
            return VerificationResult(False, {}, f"không đọc được ruleset: {exc}",
                                      reason_key="response.verify_err_unreadable",
                                      reason_params={"error": str(exc)[:200]})
        present, elements = _element_present(raw, ip)
        observed = {"nft_elements": elements, "target": ip}
        if present:
            return VerificationResult(True, observed)
        return VerificationResult(
            False, observed, f"{ip} không có trong set ratelimited_ips sau khi áp",
            reason_key="response.ratelimit_err_absent", reason_params={"ip": ip})

    async def rollback(self, plan: dict, apply_result: ApplyResult) -> RollbackResult:
        ip = str(apply_result.rollback_token.get("ip") or plan.get("ip", ""))
        if not ip:
            return RollbackResult(False, "không biết địa chỉ nào cần gỡ")
        try:
            response = await self.privileged_client.call("unrate_limit_ip", {"ip": ip})
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            return RollbackResult(False, f"privileged helper: {exc}")
        if response.get("ok"):
            return RollbackResult(True, "đã gỡ khỏi set ratelimited_ips")
        message = str(response.get("message", ""))
        if "No such file" in message or "does not exist" in message:
            return RollbackResult(True, "phần tử đã không còn — không có gì để gỡ")
        return RollbackResult(False, message or "không rõ lý do")


def _element_present(nft_json: str, ip: str) -> tuple[bool, list]:
    """Địa chỉ có trong set `ratelimited_ips` không."""
    try:
        items = json.loads(nft_json)["nftables"]
    except (ValueError, KeyError, TypeError):
        return False, []
    found: list = []
    for item in items:
        if not isinstance(item, dict):
            continue
        payload = item.get("set") or item.get("element")
        if not isinstance(payload, dict):
            continue
        if payload.get("name") != "ratelimited_ips" or payload.get("table") != "shield":
            continue
        for element in payload.get("elem") or []:
            value = element
            if isinstance(element, dict):
                inner = element.get("elem") or {}
                value = inner.get("val") if isinstance(inner, dict) else element
            found.append(value)
    return (str(ip) in {str(v) for v in found}), found
