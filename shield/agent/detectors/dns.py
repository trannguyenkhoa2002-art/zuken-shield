"""Rule DNS — phát hiện DNS của chính máy này bị đổi hoặc bị ép đi sai chỗ.

- DNS_RESOLVER_CHANGED: danh sách DNS server máy đang dùng khác baseline đã
  lưu. Đây là dấu hiệu rõ nhất của rogue DHCP hoặc malware đổi cấu hình —
  kẻ tấn công đổi DNS thì kiểm soát được mọi tên miền bạn truy cập mà không
  cần đụng vào từng gói tin.
- DNS_UNEXPECTED_SERVER: thấy truy vấn DNS đi tới server KHÔNG nằm trong
  danh sách resolver hợp lệ của hệ thống. Có thể là app tự cấu hình DNS
  riêng (trình duyệt bật DoH-fallback, Docker, VPN) — nên đây là mức
  `warning`, không phải `critical`, và dedupe theo IP server để không spam.

Baseline DNS được HỌC TỰ ĐỘNG lần đầu (giống baseline DHCP server trong
mitm.py): giả định mạng lúc mới bật app là sạch. Người dùng đổi mạng Wi-Fi
hợp lệ sẽ nhận 1 cảnh báo — đó là đánh đổi có chủ đích, vì không thể phân
biệt "đổi mạng" với "bị đổi DNS" chỉ từ dữ liệu này. Tài liệu ghi rõ để
người dùng biết cách xác nhận baseline mới.
"""

from __future__ import annotations

import logging

from shield.agent.store import Store
from shield.common.models import Alert, Event, now

logger = logging.getLogger("shield.detectors.dns")

BASELINE_DNS_SERVERS = "dns_servers"

# Nhắc lại cùng 1 server lạ nhiều nhất 1 lần / khoảng này — tránh 1 app chạy
# nền bắn hàng nghìn truy vấn DNS làm ngập bảng cảnh báo.
UNEXPECTED_REPEAT_S = 3600.0
CLEANUP_INTERVAL_S = 600.0


class DnsDetector:
    def __init__(self, store: Store) -> None:
        self.store = store
        self._reported: dict[str, float] = {}  # server_ip -> lần báo gần nhất
        self._last_cleanup = 0.0

    def _cleanup_stale(self, now_ts: float) -> None:
        if now_ts - self._last_cleanup < CLEANUP_INTERVAL_S:
            return
        self._last_cleanup = now_ts
        stale = [ip for ip, ts in self._reported.items() if now_ts - ts > UNEXPECTED_REPEAT_S]
        for ip in stale:
            del self._reported[ip]

    def handle_event(self, ev: Event) -> list[Alert]:
        self._cleanup_stale(now())
        if ev.kind == "dns_resolvers":
            return self._handle_resolvers(ev)
        if ev.kind == "dns_query_out":
            return self._handle_unexpected_server(ev)
        return []

    # --- DNS_RESOLVER_CHANGED ---

    def _handle_resolvers(self, ev: Event) -> list[Alert]:
        servers = ev.data.get("servers") or []
        if not servers:
            return []
        # Chuẩn hoá thành chuỗi có thứ tự cố định để so sánh ổn định — thứ tự
        # resolver có thể đảo giữa 2 lần đọc mà không phải là thay đổi thật.
        current = ",".join(sorted(servers))

        known = self.store.get_baseline(BASELINE_DNS_SERVERS)
        if known is None:
            self.store.set_baseline(BASELINE_DNS_SERVERS, current)
            logger.info("Đã học baseline DNS server: %s", current)
            return []

        if current == known:
            return []

        self.store.set_baseline(BASELINE_DNS_SERVERS, current)
        return [
            Alert(
                ts=now(),
                rule_id="DNS_RESOLVER_CHANGED",
                severity="critical",
                title="DNS server của máy đã bị đổi",
                detail=(
                    f"Trước đây máy dùng DNS: {known}. Bây giờ là: {current}. "
                    "Nếu bạn không tự đổi và cũng không vừa chuyển sang mạng "
                    "Wi-Fi khác, đây là dấu hiệu rogue DHCP hoặc phần mềm độc "
                    "hại đổi cấu hình DNS."
                ),
                subject=current,
                evidence={"baseline": known, "current": current},
                playbook=["snapshot_state", "start_capture"],
            )
        ]

    # --- DNS_UNEXPECTED_SERVER ---

    def _handle_unexpected_server(self, ev: Event) -> list[Alert]:
        server_ip = ev.data.get("server_ip")
        if not server_ip:
            return []

        now_ts = now()
        last = self._reported.get(server_ip)
        if last is not None and now_ts - last <= UNEXPECTED_REPEAT_S:
            return []
        self._reported[server_ip] = now_ts

        known = ev.data.get("known") or []
        return [
            Alert(
                ts=now_ts,
                rule_id="DNS_UNEXPECTED_SERVER",
                severity="warning",
                title=f"Có truy vấn DNS đi tới server lạ {server_ip}",
                detail=(
                    f"Máy đang gửi truy vấn DNS tới {server_ip}, không nằm trong "
                    f"danh sách resolver hệ thống ({', '.join(known) or 'chưa rõ'}). "
                    "Có thể là ứng dụng tự cấu hình DNS riêng (trình duyệt, VPN, "
                    "Docker) — hoặc DNS đang bị ép đi qua máy khác."
                ),
                subject=server_ip,
                evidence={"server_ip": server_ip, "known_resolvers": known},
                playbook=["snapshot_state"],
            )
        ]
