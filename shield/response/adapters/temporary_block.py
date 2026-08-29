"""Chặn một IP có thời hạn — action Level 2 đầu tiên (mục 4.3).

Đây là action duy nhất ở 2.0 đủ điều kiện tự động: đảo ngược được, phạm vi một
địa chỉ, có TTL, và kiểm chứng được từ trạng thái kernel.

Phần khó không phải chặn mà là **không chặn nhầm**. Chặn gateway thì cả máy mất
mạng; chặn DNS resolver thì mọi thứ dựa vào tên miền hỏng; chặn địa chỉ quản trị
thì không ai vào sửa được. Ba thứ đó nằm trong tiền điều kiện, và tiền điều kiện
được kiểm TRƯỚC khi áp chứ không phải sau.
"""

from __future__ import annotations

import ipaddress
import json

from shield.response.adapters.base import (
    ApplyResult,
    CheckResult,
    Impact,
    RollbackResult,
    VerificationResult,
)

# Địa chỉ không bao giờ được chặn, dù policy nói gì. Mục 4.3: "allowlist chống
# block management/DNS/gateway".
ALWAYS_PROTECTED = ("127.0.0.0/8", "::1/128", "0.0.0.0/32", "255.255.255.255/32")


def protected_reason(ip: str, *, gateway: str = "", resolvers=(), management: str = "") -> str:
    """Vì sao KHÔNG được chặn địa chỉ này. Chuỗi rỗng nghĩa là được phép."""
    return protected_reason_key(ip, gateway=gateway, resolvers=resolvers,
                                management=management)[1]


# (khoá dịch, câu tiếng Việt dự phòng). Câu dự phòng vẫn cần cho nhật ký và
# báo cáo — những nơi không có bảng dịch.
_PROTECTED_REASONS = {
    "invalid": ("response.block_err_invalid", "địa chỉ không hợp lệ"),
    "reserved": ("response.block_err_reserved", "nằm trong dải luôn được bảo vệ"),
    "multicast": ("response.block_err_multicast", "địa chỉ multicast"),
    "gateway": ("response.block_err_gateway",
                "đây là gateway — chặn nó là tự cắt mạng của chính máy này"),
    "management": ("response.block_err_management",
                   "đây là địa chỉ quản trị — chặn nó là mất đường vào để sửa"),
    "resolver": ("response.block_err_resolver",
                 "đây là máy chủ DNS — chặn nó làm hỏng mọi thứ dựa vào tên miền"),
}


def protected_reason_key(ip: str, *, gateway: str = "", resolvers=(),
                         management: str = "") -> tuple[str, str]:
    """(khoá dịch, câu dự phòng). Cả hai rỗng nghĩa là được phép chặn."""
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return _PROTECTED_REASONS["invalid"]
    for network in ALWAYS_PROTECTED:
        if address in ipaddress.ip_network(network):
            return _PROTECTED_REASONS["reserved"]
    if address.is_multicast:
        return _PROTECTED_REASONS["multicast"]
    if gateway and str(address) == str(gateway):
        return _PROTECTED_REASONS["gateway"]
    if management and str(address) == str(management):
        return _PROTECTED_REASONS["management"]
    if any(str(address) == str(item) for item in resolvers):
        return _PROTECTED_REASONS["resolver"]
    return ("", "")


class TemporaryBlockAdapter:
    action = "block_ip"
    reversible = True
    human_only = False

    def __init__(self, privileged_client, *, gateway: str = "", resolvers=(),
                 management: str = "", nft_reader=None) -> None:
        self.privileged_client = privileged_client
        self.gateway = gateway
        self.resolvers = tuple(resolvers)
        self.management = management
        # Hàm đọc ruleset nftables. Tách ra để kiểm chứng test được mà không
        # cần root — và để rõ rằng verify ĐỌC HỆ THỐNG chứ không hỏi executor.
        self.nft_reader = nft_reader

    async def preview(self, plan: dict) -> Impact:
        ip = str(plan.get("ip", ""))
        return Impact(
            summary=f"Chặn mọi lưu lượng đi và đến {ip} trong {int(plan.get('ttl_s', 0))} giây.",
            affected=({"service": "Kết nối tới/từ địa chỉ này", "target": ip},),
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
            # Chặn không có hạn là chặn vĩnh viễn, và không ai nhớ để gỡ.
            return CheckResult(False, ("ttl_within_limit",), "chặn phải có thời hạn",
                               reason_key="response.block_err_no_ttl")
        if self.privileged_client is None:
            return CheckResult(False, ("privileged_helper_available",),
                               "không có privileged helper để áp luật",
                               reason_key="response.block_err_no_helper")
        return CheckResult(True)

    async def apply(self, plan: dict, idempotency_key: str) -> ApplyResult:
        ip = str(plan.get("ip", ""))
        try:
            response = await self.privileged_client.call("block_ip", {"ip": ip})
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            return ApplyResult(False, f"privileged helper: {exc}")
        if not response.get("ok"):
            return ApplyResult(False, str(response.get("message", "không rõ lý do")))
        return ApplyResult(True, "đã thêm vào set blocked_ips",
                           rollback_token={"ip": ip, "idempotency_key": idempotency_key})

    async def verify(self, plan: dict, apply_result: ApplyResult) -> VerificationResult:
        """Đọc set nftables và tìm địa chỉ. KHÔNG tin thông điệp của apply().

        Mục 3.4: "Command exit code 0 không đồng nghĩa containment đã thành
        công; phải verify."
        """
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
        present, detail = _element_present(raw, ip)
        if present:
            return VerificationResult(True, {"nft_elements": detail, "target": ip})
        return VerificationResult(
            False, {"nft_elements": detail, "target": ip},
            f"{ip} không có trong set blocked_ips sau khi áp",
            reason_key="response.verify_err_absent", reason_params={"ip": ip},
        )

    async def rollback(self, plan: dict, apply_result: ApplyResult) -> RollbackResult:
        ip = str(apply_result.rollback_token.get("ip") or plan.get("ip", ""))
        if not ip:
            return RollbackResult(False, "không biết địa chỉ nào cần gỡ")
        try:
            response = await self.privileged_client.call("unblock_ip", {"ip": ip})
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            return RollbackResult(False, f"privileged helper: {exc}")
        if response.get("ok"):
            return RollbackResult(True, "đã gỡ khỏi set blocked_ips")
        # Gỡ một phần tử không tồn tại là thành công về mặt kết quả: đích đến
        # là "địa chỉ này không bị chặn nữa", và nó đã đúng. Rollback phải
        # idempotent, nếu không mỗi lần thử lại đều báo lỗi và không ai dừng.
        message = str(response.get("message", ""))
        if "No such file" in message or "does not exist" in message:
            return RollbackResult(True, "phần tử đã không còn — không có gì để gỡ")
        return RollbackResult(False, message or "không rõ lý do")


def _element_present(nft_json: str, ip: str) -> tuple[bool, list]:
    """Địa chỉ có trong set `blocked_ips` của `table inet shield` không."""
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
        if payload.get("name") != "blocked_ips" or payload.get("table") != "shield":
            continue
        elements = payload.get("elem") or []
        for element in elements if isinstance(elements, list) else []:
            value = element
            if isinstance(element, dict):
                inner = element.get("elem") or {}
                value = inner.get("val") if isinstance(inner, dict) else element
            found.append(value)
    return (str(ip) in {str(v) for v in found}), found
