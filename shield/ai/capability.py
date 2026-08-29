"""Capability token và kill switch cho AI (mục 5.4 — excessive agency).

Ba cơ chế, mỗi cái chặn một dạng hỏng khác nhau:

1. **Capability token.** Một lượt điều tra nhận một token có TTL ngắn, gắn với
   đúng incident đó, và dùng một lần cho mỗi tool. Model không giữ được quyền
   sang lượt sau, và không mượn được quyền của lượt khác.
2. **Quota theo model và theo incident.** Một model lặp vô hạn sẽ chạm trần và
   dừng, thay vì giữ một luồng mãi mãi.
3. **Kill switch toàn cục.** Tắt sạch mọi tool execution của AI mà KHÔNG chạm
   vào detection. Đây là thứ người vận hành cần khi họ nghi ngờ chính lớp AI —
   và nếu tắt AI cũng làm ngừng phát hiện thì họ sẽ không dám tắt.

Model không bao giờ nhìn thấy token: nó nằm ở orchestrator. Model chỉ gọi tên
tool, và orchestrator quyết định lời gọi đó có quyền hay không. Đưa token cho
model nghĩa là đưa cho nó một thứ để rò rỉ.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field

# TTL ngắn có chủ ý. Một lượt điều tra bình thường xong trong vài giây; token
# sống 5 phút đã là rộng rãi. Token sống lâu là token bị dùng lại.
DEFAULT_TTL_S = 300.0
DEFAULT_TOOL_QUOTA = 24
DEFAULT_INCIDENT_QUOTA_PER_HOUR = 6

KILL_SWITCH_ENV = "SHIELD_AI_KILL_SWITCH"


class CapabilityDenied(RuntimeError):
    """Lời gọi không có quyền. Đếm riêng, không nuốt."""


def ai_tools_killed() -> bool:
    """Kill switch toàn cục đang bật không.

    Đọc biến môi trường MỖI LẦN, không cache: người vận hành bật nó lúc đang có
    sự cố, và một giá trị đã cache nghĩa là công tắc không có tác dụng cho tới
    lần khởi động lại — đúng lúc họ không muốn khởi động lại gì cả.
    """
    return os.environ.get(KILL_SWITCH_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class CapabilityToken:
    token: str
    incident_id: str
    allowed_tools: frozenset[str]
    issued_ts: float
    ttl_s: float = DEFAULT_TTL_S
    tool_budget: int = DEFAULT_TOOL_QUOTA
    used: int = 0
    revoked: bool = False

    def expired(self, at: float) -> bool:
        return at - self.issued_ts > self.ttl_s

    def to_dict(self) -> dict:
        return {
            # KHÔNG bao giờ xuất chính chuỗi token ra ngoài: dict này đi vào
            # nhật ký và nhật ký sống lâu hơn token.
            "incident_id": self.incident_id, "allowed_tools": sorted(self.allowed_tools),
            "issued_ts": self.issued_ts, "ttl_s": self.ttl_s,
            "tool_budget": self.tool_budget, "used": self.used, "revoked": self.revoked,
        }


@dataclass
class CapabilityBroker:
    """Cấp và kiểm token. Điểm thực thi quyền DUY NHẤT."""

    clock: object = time.time
    incident_quota_per_hour: int = DEFAULT_INCIDENT_QUOTA_PER_HOUR
    _tokens: dict = field(default_factory=dict)
    _incident_history: dict = field(default_factory=dict)
    denials: int = 0

    def issue(self, incident_id: str, allowed_tools, *, ttl_s: float = DEFAULT_TTL_S,
              tool_budget: int = DEFAULT_TOOL_QUOTA) -> CapabilityToken:
        now = float(self.clock())
        history = [ts for ts in self._incident_history.get(incident_id, [])
                   if now - ts < 3600]
        if len(history) >= self.incident_quota_per_hour:
            self.denials += 1
            raise CapabilityDenied(
                f"incident {incident_id} đã dùng hết {self.incident_quota_per_hour} "
                "lượt điều tra trong một giờ")
        history.append(now)
        self._incident_history[incident_id] = history

        token = CapabilityToken(
            token=secrets.token_urlsafe(24), incident_id=str(incident_id),
            allowed_tools=frozenset(str(name) for name in allowed_tools),
            issued_ts=now, ttl_s=float(ttl_s), tool_budget=int(tool_budget),
        )
        self._tokens[token.token] = token
        self._prune(now)
        return token

    def check(self, token_value: str, tool: str, incident_id: str) -> CapabilityToken:
        """Lời gọi này có quyền không. Ném CapabilityDenied nếu không."""
        now = float(self.clock())
        if ai_tools_killed():
            self.denials += 1
            raise CapabilityDenied("kill switch AI đang bật — mọi tool execution bị chặn")
        token = self._tokens.get(str(token_value))
        if token is None:
            self.denials += 1
            raise CapabilityDenied("token không tồn tại")
        if token.revoked:
            self.denials += 1
            raise CapabilityDenied("token đã bị thu hồi")
        if token.expired(now):
            self.denials += 1
            raise CapabilityDenied("token đã hết hạn")
        if token.incident_id != str(incident_id):
            # Mượn quyền của lượt điều tra khác. Đây là dấu hiệu rõ ràng của
            # một thứ đang đi sai đường, không phải một nhầm lẫn vô hại.
            self.denials += 1
            raise CapabilityDenied("token thuộc về một incident khác")
        if tool not in token.allowed_tools:
            self.denials += 1
            raise CapabilityDenied(f"token không cho phép tool {tool!r}")
        if token.used >= token.tool_budget:
            self.denials += 1
            raise CapabilityDenied(f"đã dùng hết {token.tool_budget} lượt gọi tool")
        token.used += 1
        return token

    def revoke(self, token_value: str) -> bool:
        token = self._tokens.get(str(token_value))
        if token is None:
            return False
        token.revoked = True
        return True

    def revoke_all(self) -> int:
        """Thu hồi mọi token. Dùng khi bật kill switch lúc đang chạy."""
        count = 0
        for token in self._tokens.values():
            if not token.revoked:
                token.revoked = True
                count += 1
        return count

    def _prune(self, now: float) -> None:
        # Bảng token có trần: nó không được trở thành chỗ rò bộ nhớ trên một
        # agent chạy hàng tháng.
        stale = [value for value, token in self._tokens.items()
                 if token.expired(now) or token.revoked]
        for value in stale[: max(0, len(self._tokens) - 256)]:
            self._tokens.pop(value, None)
        for value in stale:
            if len(self._tokens) <= 256:
                break
            self._tokens.pop(value, None)

    def stats(self) -> dict:
        return {"active_tokens": sum(1 for t in self._tokens.values() if not t.revoked),
                "denials": self.denials,
                "kill_switch": ai_tools_killed()}
