"""4 rule đọc log máy (KE-HOACH-SHIELD.md mục 2.4).

- LOCAL_SSH_BRUTEFORCE: sshd failed password >=5 lần từ cùng IP trong 1 cửa
  sổ thời gian (mặc định 5 phút — bruteforce thật thường dồn dập hơn nhiều).
- LOCAL_SUDO_FAIL: mỗi lần sudo thất bại (dedupe theo user đã có sẵn ở Store).
- LOCAL_NEW_USB: USB mới cắm — đề phòng USB lạ.
- LOCAL_PROMISC_MODE: interface vào promiscuous mode — rất đáng chú ý, NHƯNG
  phải lọc bỏ interface mà chính Shield đang sniff (arp_sniffer/conn_watch),
  nếu không sẽ tự báo động vì chính mình.
"""

from __future__ import annotations

from shield.agent.store import Store
from shield.common.models import Alert, Event, now

SSH_BRUTEFORCE_THRESHOLD = 5
SSH_BRUTEFORCE_WINDOW_S = 300.0

# _ssh_fails chỉ lọc theo cửa sổ thời gian khi CHÍNH src_ip đó có lần fail
# mới — IP ngừng dò để lại key rỗng nằm mãi trong dict, rò rỉ bộ nhớ chậm.
CLEANUP_INTERVAL_S = 300.0


class LocalLogDetector:
    def __init__(self, store: Store, own_interfaces: set[str] | None = None) -> None:
        self.store = store
        self.own_interfaces = own_interfaces or set()
        self._ssh_fails: dict[str, list[float]] = {}
        self._last_cleanup = 0.0

    def _cleanup_stale(self, now_ts: float) -> None:
        if now_ts - self._last_cleanup < CLEANUP_INTERVAL_S:
            return
        self._last_cleanup = now_ts
        stale_ips = [
            ip
            for ip, fails in self._ssh_fails.items()
            if not any(now_ts - t <= SSH_BRUTEFORCE_WINDOW_S for t in fails)
        ]
        for ip in stale_ips:
            del self._ssh_fails[ip]

    def handle_event(self, ev: Event) -> list[Alert]:
        self._cleanup_stale(now())
        if ev.kind == "ssh_failed_password":
            return self._handle_ssh_failed(ev)
        if ev.kind == "sudo_failed":
            return self._handle_sudo_failed(ev)
        if ev.kind == "usb_new":
            return self._handle_usb_new(ev)
        if ev.kind == "promisc_mode":
            return self._handle_promisc(ev)
        return []

    def _handle_ssh_failed(self, ev: Event) -> list[Alert]:
        src_ip = ev.data.get("src_ip")
        if not src_ip:
            return []

        now_ts = now()
        fails = self._ssh_fails.setdefault(src_ip, [])
        fails[:] = [t for t in fails if now_ts - t <= SSH_BRUTEFORCE_WINDOW_S]
        fails.append(now_ts)
        if len(fails) < SSH_BRUTEFORCE_THRESHOLD:
            return []

        return [
            Alert(
                ts=now_ts,
                rule_id="LOCAL_SSH_BRUTEFORCE",
                severity="warning",
                title=f"SSH bị dò mật khẩu từ {src_ip}",
                detail=(
                    f"{len(fails)} lần đăng nhập SSH sai trong "
                    f"{SSH_BRUTEFORCE_WINDOW_S / 60:.0f} phút từ {src_ip}."
                ),
                subject=src_ip,
                evidence={
                    "src_ip": src_ip,
                    "fail_count": len(fails),
                    "window_min": int(SSH_BRUTEFORCE_WINDOW_S / 60),
                },
                playbook=["block_ip"],
            )
        ]

    def _handle_sudo_failed(self, ev: Event) -> list[Alert]:
        user = ev.data.get("user", "unknown")
        return [
            Alert(
                ts=now(),
                rule_id="LOCAL_SUDO_FAIL",
                severity="warning",
                title=f"sudo thất bại (user: {user})",
                detail=ev.data.get("message", ""),
                subject=user,
                evidence={"user": user, "message": ev.data.get("message", "")},
                playbook=[],
            )
        ]

    def _handle_usb_new(self, ev: Event) -> list[Alert]:
        message = ev.data.get("message", "")
        return [
            Alert(
                ts=now(),
                rule_id="LOCAL_NEW_USB",
                severity="info",
                title="Có thiết bị USB mới được cắm vào",
                detail=message,
                subject=message[:80] or "usb",
                evidence={"message": message},
                playbook=[],
            )
        ]

    def _handle_promisc(self, ev: Event) -> list[Alert]:
        interface = ev.data.get("interface")
        if not interface or interface in self.own_interfaces:
            return []

        return [
            Alert(
                ts=now(),
                rule_id="LOCAL_PROMISC_MODE",
                severity="critical",
                title=f"Interface {interface} chuyển sang promiscuous mode",
                detail=(
                    f"Có ai/chương trình gì đó bật sniff trên {interface} nhưng không "
                    "phải Shield. Đáng nghi — có thể là công cụ nghe lén khác đang chạy."
                ),
                subject=interface,
                evidence={"interface": interface, "message": ev.data.get("message", "")},
                playbook=["snapshot_state"],
            )
        ]
