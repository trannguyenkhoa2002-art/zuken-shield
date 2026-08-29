"""Trần tốc độ dùng CHUNG cho các collector, kèm bộ đếm số bị bỏ.

Trước file này, `kernel.py` có `_RateLimiter` riêng, còn `conn_watch` và
`arp_sniffer` — hai collector sniff gói tin, tức là hai collector mà kẻ tấn
công điều khiển được tốc độ đầu vào — thì không có trần nào cả.

Cụ thể hơn: `on_packet` của scapy chạy trên thread riêng và gọi thẳng
`asyncio.run_coroutine_threadsafe` cho MỖI gói. Một cơn SYN flood — đúng thứ
`SCAN_PORTSCAN` sinh ra để phát hiện — dồn future không giới hạn vào event
loop. Ở trạng thái bình thường `tcp_ack` đã là 41% toàn bộ telemetry.

Hai nguyên tắc của file này:

1. Trần áp TRƯỚC khi lên lịch bất cứ thứ gì trên event loop. Chặn sau khi đã
   xếp hàng thì không chặn gì cả.
2. Bỏ thì phải ĐẾM và phải nổi lên `collector_health`. Mất dữ liệu mà không có
   bộ đếm là mất dữ liệu trong im lặng, và nó trông y hệt như "mạng yên tĩnh".
"""

from __future__ import annotations


class RateLimiter:
    """Trần theo giây cho mỗi loại, có đếm số bị bỏ.

    Gọi được từ thread khác event loop: `allow()` chỉ đọc/ghi số nguyên và
    dict, và mỗi collector chỉ có MỘT thread sniff gọi vào. Bộ đếm `dropped`
    được đọc từ phía asyncio để báo sức khoẻ — đọc một số nguyên là thao tác
    nguyên tử, nên không cần khoá và cũng không nên có khoá: một khoá trên
    đường xử lý mỗi gói tin là chỗ nghẽn tự tạo.
    """

    def __init__(self, limits: dict[str, int]) -> None:
        self.limits = dict(limits)
        self._window = 0.0
        self._count: dict[str, int] = {}
        self.dropped: dict[str, int] = {}

    def allow(self, kind: str, at: float) -> bool:
        second = int(at)
        if second != self._window:
            self._window = second
            self._count.clear()
        used = self._count.get(kind, 0)
        if used >= self.limits.get(kind, 0):
            self.dropped[kind] = self.dropped.get(kind, 0) + 1
            return False
        self._count[kind] = used + 1
        return True

    def total_dropped(self) -> int:
        """Tổng số event bị bỏ vì trần tốc độ, kể từ khi collector này chạy.

        Đây là con số cho `collector_health.dropped_events`. Nó KHÁC với
        `losing_data_since_last_check()`: cái kia trả lời "có đang mất ngay bây
        giờ không" và quyết định healthy; cái này là tổng cộng dồn, và một tổng
        cộng dồn KHÔNG được tự biến collector thành hỏng — một chớp lưu lượng
        hôm qua không có nghĩa là hôm nay đang mù.
        """
        return sum(self.dropped.values())

    def drop_summary(self) -> str:
        """Một dòng cho `collector_health`. Rỗng khi chưa bỏ gì."""
        if not self.dropped:
            return ""
        parts = ", ".join(f"{kind}={count}" for kind, count in sorted(self.dropped.items()))
        return f"đã bỏ do giới hạn tốc độ: {parts}"

    def losing_data_since_last_check(self) -> bool:
        """Có đang mất dữ liệu NGAY BÂY GIỜ không — khác với "đã từng mất".

        Bộ đếm `dropped` cộng dồn và không bao giờ giảm. Dùng thẳng nó làm
        điều kiện khoẻ/không khoẻ thì một cơn bùng nổ ba gói lúc 14 giờ sẽ để
        component đó ở trạng thái "hỏng" mãi mãi — và một component báo hỏng
        vĩnh viễn dạy người ta bỏ qua nó, đúng thứ Shield tồn tại để tránh.

        Đã xảy ra thật: chính lượt quét `nmap -sn`/`arp-scan` của Shield sinh
        ra một chớp ICMP/ARP vượt trần, và `arp_ndp_dhcp` báo `degraded` vĩnh
        viễn vì 3 gói.

        So với lần hỏi trước: TĂNG nghĩa là đang mất, đứng yên nghĩa là không.
        """
        total = sum(self.dropped.values())
        previous = getattr(self, "_reported_drops", 0)
        self._reported_drops = total
        return total > previous
