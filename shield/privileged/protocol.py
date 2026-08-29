"""Strict request validation shared by helper and unprivileged coordinator."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
ALLOWED_ACTIONS = {
    "health", "block_ip", "unblock_ip", "block_mac", "unblock_mac", "stop_process",
    # Cách ly endpoint (KE-HOACH-SHIELD-2.0.md mục 0.2). CỐ Ý không nhận `ttl_s`:
    # table nftables này không tự hết hạn ở kernel, việc gỡ đúng hạn là của
    # dead-man switch phía agent. Nhận một tham số mà helper không dùng chỉ tạo
    # ảo giác rằng kernel sẽ tự dọn.
    "isolate_endpoint", "release_isolation",
    # Bậc thang giữa "không làm gì" và "chặn hẳn".
    "rate_limit_ip", "unrate_limit_ip",
}


@dataclass(frozen=True)
class PrivilegedRequest:
    request_id: str
    action: str
    params: dict

    @classmethod
    def parse(cls, raw: dict) -> "PrivilegedRequest":
        if not isinstance(raw, dict) or set(raw) != {"request_id", "action", "params"}:
            raise ValueError("invalid helper request envelope")
        request_id, action, params = raw["request_id"], raw["action"], raw["params"]
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            raise ValueError("invalid request id")
        if action not in ALLOWED_ACTIONS or not isinstance(params, dict):
            raise ValueError("action is not allowlisted")
        if action == "health":
            if params:
                raise ValueError("health requires no parameters")
        elif action.endswith("_ip"):
            if set(params) != {"ip"}:
                raise ValueError("IP action requires exactly ip")
            try:
                ip = str(ipaddress.ip_address(params["ip"]))
            except ValueError as exc:
                raise ValueError("invalid IP") from exc
            if ":" in ip:  # current nft set is IPv4-only
                raise ValueError("IPv6 firewall response is not enabled")
            params = {"ip": ip}
        elif action.endswith("_mac"):
            mac = str(params.get("mac", "")).lower()
            if set(params) != {"mac"} or not _MAC.fullmatch(mac):
                raise ValueError("invalid MAC")
            params = {"mac": mac}
        elif action == "isolate_endpoint":
            if set(params) - {"management_ip", "preserve_dns"} or "management_ip" not in params:
                raise ValueError("isolate_endpoint requires management_ip")
            try:
                address = ipaddress.ip_address(str(params["management_ip"]))
            except ValueError as exc:
                raise ValueError("invalid management IP") from exc
            if address.version != 4:
                raise ValueError("isolation is IPv4-only")
            # Loopback/unspecified/multicast làm ngoại lệ quản trị vô nghĩa: sau
            # khi áp policy drop sẽ không còn đường nào vào máy.
            if address.is_unspecified or address.is_multicast or address.is_loopback:
                raise ValueError("unsafe management address")
            params = {"management_ip": str(address), "preserve_dns": bool(params.get("preserve_dns", False))}
        elif action == "release_isolation":
            if params:
                raise ValueError("release_isolation requires no parameters")
        elif action == "stop_process":
            if set(params) != {"pid", "start_ticks"}:
                raise ValueError("stop_process requires exact PID identity")
            pid = int(params["pid"])
            ticks = str(params["start_ticks"])
            if pid <= 1 or not ticks.isdigit():
                raise ValueError("invalid PID identity")
            params = {"pid": pid, "start_ticks": ticks}
        return cls(request_id, action, params)
