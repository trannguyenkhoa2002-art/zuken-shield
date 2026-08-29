"""Công tắc giám sát điều khiển từ UI — tắt/tạm dừng không cần chạy lệnh.

Vì sao cần: Shield chạy `arp-scan` mỗi 60 giây và `nmap -sn` mỗi 15 phút
(collectors/discovery.py). Trên mạng nhà thì vô hại, nhưng trên mạng trường
học / cơ quan / quán cà phê, NAC và IDS đánh dấu đó là quét mạng trái phép.
Người dùng phải tắt được NGAY từ trong app, không phải đi tìm lệnh
`systemctl` — lúc cần tắt gấp thì không ai kịp mở terminal.

Ba mức, tách bạch theo mức độ ồn:

- `active_scan` — thứ CHỦ ĐỘNG gửi gói ra mạng: arp-scan, nmap, self audit,
  router poll, evasion probe. Đây là mức gây rắc rối với IT của trường.
- `capture`     — tcpdump/pcap theo dõi 1 host và tarpit. Không quét, nhưng
  ghi đĩa và mở cổng lắng nghe.
- `passive`     — sniff ARP/DNS/SYN và đọc log máy. Không phát ra gói nào.

Tạm dừng luôn được ghi vào audit log. Đây là điều kiện để Guardian (mục B2)
phân biệt "người dùng chủ động tắt" với "kẻ tấn công vừa giết Shield" — nếu
không ghi lại, hai việc đó nhìn giống hệt nhau.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# Thứ tự từ ồn nhất tới im nhất. `pause("all")` dừng cả ba.
SCOPES = ("active_scan", "capture", "passive")
ALL = "all"

# Trần thời gian tạm dừng: 24 giờ. Không cho "tạm dừng vĩnh viễn" bằng
# duration — muốn tắt hẳn thì dùng shutdown, để trạng thái đó nhìn thấy được
# thay vì một Shield im lặng mà người dùng tưởng đang chạy.
MAX_PAUSE_S = 24 * 3600
DEFAULT_PAUSE_S = 3600.0


def normalize_scopes(scope: str) -> frozenset[str]:
    if scope == ALL:
        return frozenset(SCOPES)
    if scope in SCOPES:
        return frozenset({scope})
    raise ValueError(f"unknown monitoring scope: {scope!r}")


@dataclass(frozen=True)
class SwitchState:
    paused: frozenset[str]
    resume_ts: dict[str, float]
    reason: str
    changed_ts: float

    def to_dict(self) -> dict:
        return {
            "paused": sorted(self.paused),
            "resume_ts": dict(self.resume_ts),
            "reason": self.reason,
            "changed_ts": self.changed_ts,
            "scopes": list(SCOPES),
        }


class MonitoringSwitch:
    """Trạng thái bật/tắt dùng chung giữa các vòng lặp collector.

    Cố ý KHÔNG dùng asyncio.Event: các vòng lặp đều đã có `await sleep(...)`
    riêng, nên chỉ cần hỏi `allows()` ở đầu mỗi vòng là đủ. Không có khoá,
    không có await — gọi được từ bất cứ đâu, kể cả trong hàm đồng bộ.
    """

    def __init__(self, store=None, clock=time.time) -> None:
        self.store = store
        self._clock = clock
        self._paused: dict[str, float] = {}  # scope -> resume_ts (0 = vô hạn)
        self._reason = ""
        self._changed_ts = clock()

    # ------------------------------------------------------------------ đọc
    def allows(self, scope: str) -> bool:
        """True nếu scope đang được phép chạy. Tự hết hạn khi tới resume_ts."""
        if scope not in SCOPES:
            return True
        resume_ts = self._paused.get(scope)
        if resume_ts is None:
            return True
        if resume_ts and self._clock() >= resume_ts:
            del self._paused[scope]
            return True
        return False

    @property
    def active_scan_allowed(self) -> bool:
        return self.allows("active_scan")

    def state(self) -> SwitchState:
        for scope in list(self._paused):
            self.allows(scope)  # dọn scope đã hết hạn
        return SwitchState(
            frozenset(self._paused), dict(self._paused), self._reason, self._changed_ts
        )

    # ------------------------------------------------------------------ ghi
    def pause(self, scope: str = ALL, duration_s: float | None = None, reason: str = "") -> SwitchState:
        scopes = normalize_scopes(scope)
        if duration_s is None:
            resume_ts = 0.0  # tới khi người dùng bật lại
        else:
            duration = max(0.0, min(float(duration_s), MAX_PAUSE_S))
            if duration <= 0:
                raise ValueError("pause duration must be positive")
            resume_ts = self._clock() + duration
        for item in scopes:
            self._paused[item] = resume_ts
        self._reason = str(reason)[:200]
        self._changed_ts = self._clock()
        self._audit("monitoring_pause", {"scope": scope, "duration_s": duration_s, "reason": self._reason})
        return self.state()

    def resume(self, scope: str = ALL) -> SwitchState:
        for item in normalize_scopes(scope):
            self._paused.pop(item, None)
        self._reason = ""
        self._changed_ts = self._clock()
        self._audit("monitoring_resume", {"scope": scope})
        return self.state()

    def _audit(self, action: str, params: dict) -> None:
        if self.store is None:
            return
        try:
            self.store.add_audit_log(action, params, "ok")
            self.store.add_forensic_record("switch", {"action": action, **params, "ts": self._clock()})
        except Exception:  # noqa: BLE001 - công tắc không bao giờ được chết vì log
            pass


# --------------------------------------------------------------------------
# Truy cập dùng chung.
#
# Cố ý dùng một instance ở mức module thay vì truyền qua ~15 chữ ký hàm:
# collector nằm rải rác ở `shield/agent/collectors/*` và mỗi cái lại có chữ ký
# riêng, luồn tham số qua hết sẽ tạo một diff to mà khó soát. Đổi lại, phải có
# `reset_switch()` để test không rò trạng thái sang nhau.
_SWITCH: MonitoringSwitch | None = None


def set_switch(switch: MonitoringSwitch) -> MonitoringSwitch:
    global _SWITCH
    _SWITCH = switch
    return switch


def current_switch() -> MonitoringSwitch:
    global _SWITCH
    if _SWITCH is None:
        _SWITCH = MonitoringSwitch()
    return _SWITCH


def reset_switch() -> None:
    global _SWITCH
    _SWITCH = None


def allows(scope: str) -> bool:
    """Cổng chặn gọn cho collector: `if not allows("active_scan"): return`."""
    return current_switch().allows(scope)
