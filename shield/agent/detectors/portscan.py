"""Rule SCAN_PORTSCAN (KE-HOACH-SHIELD.md mục 2.3).

Đếm số port đích khác nhau từ mỗi source IP trong cửa sổ 10s; vượt ngưỡng ->
báo. Phân biệt SYN-scan (half-open, không ACK) với connect-scan (có ACK hoàn
tất handshake) bằng việc có thấy Event(kind="tcp_ack") cho port đó hay không
— thông tin hữu ích khi điều tra, đưa vào evidence (không đổi mức nghiêm trọng).

Ngưỡng chỉnh được qua constructor vì mDNS/SSDP/app đồng bộ LAN có thể chạm
ngưỡng thấp (rủi ro false positive, xem mục 6 kế hoạch) — Settings ở giai
đoạn 5 sẽ cho chỉnh trong UI.
"""

from __future__ import annotations

from shield.agent.store import Store
from shield.common.models import Alert, Event, now

DEFAULT_PORT_THRESHOLD = 15
DEFAULT_WINDOW_S = 10.0

# _syn_events chỉ lọc theo cửa sổ thời gian khi CHÍNH src_ip đó có SYN mới —
# IP ngừng gửi để lại key rỗng nằm mãi. _acked_ports trước đây còn không có
# khái niệm hết hạn nào cả (set[int] không có timestamp) — mọi cổng từng ACK
# từ mọi IP từng kết nối tới máy bạn tích luỹ VÔ THỜI HẠN. Dọn định kỳ thay
# vì mỗi event để rẻ.
CLEANUP_INTERVAL_S = 300.0
ACK_RETENTION_S = 3600.0  # nhớ ACK 1h để phân loại connect-scan, không cần lâu hơn


class PortscanDetector:
    def __init__(
        self,
        store: Store,
        port_threshold: int = DEFAULT_PORT_THRESHOLD,
        window_s: float = DEFAULT_WINDOW_S,
    ) -> None:
        self.store = store
        self.port_threshold = port_threshold
        self.window_s = window_s
        # State trong RAM, cửa sổ ngắn — không cần bền qua restart.
        self._syn_events: dict[str, list[tuple[int, float]]] = {}
        self._acked_ports: dict[str, dict[int, float]] = {}  # ip -> {port: last_ack_ts}
        self._last_cleanup = 0.0
        # Bằng chứng ACK đến từ bản đếm hay từ gói tin. Ghi vào evidence để
        # người điều tra biết mình đang đọc loại bằng chứng nào.
        self._ack_from_aggregate = False

    def _cleanup_stale(self, now_ts: float) -> None:
        if now_ts - self._last_cleanup < CLEANUP_INTERVAL_S:
            return
        self._last_cleanup = now_ts

        stale_ips = [
            ip
            for ip, events in self._syn_events.items()
            if not any(now_ts - t <= self.window_s for _, t in events)
        ]
        for ip in stale_ips:
            del self._syn_events[ip]

        for ip in list(self._acked_ports):
            ports = self._acked_ports[ip]
            for port in [p for p, t in ports.items() if now_ts - t > ACK_RETENTION_S]:
                del ports[port]
            if not ports:
                del self._acked_ports[ip]

    def handle_event(self, ev: Event) -> list[Alert]:
        self._cleanup_stale(now())
        # `tcp_ack` (một gói) và `tcp_ack_window` (bản đếm một cửa sổ) mang
        # cùng thông tin mà detector này dùng: cặp (src_ip, dst_port) đã bắt
        # tay xong. Nhận cả hai — dữ liệu lịch sử và probe bản cũ vẫn gửi loại
        # thứ nhất, còn conn_watch từ Phase 2 gửi loại thứ hai.
        if ev.kind in {"tcp_ack", "tcp_ack_seen", "tcp_ack_window"}:
            self._handle_ack(ev)
            return []
        if ev.kind == "tcp_syn":
            return self._handle_syn(ev)
        return []

    def _handle_ack(self, ev: Event) -> None:
        src_ip = ev.data.get("src_ip")
        port = ev.data.get("dst_port")
        if src_ip and port is not None:
            # `tcp_ack_seen` LÀ một gói tin thật đã quan sát được — nó chỉ là
            # gói đầu tiên của khoá trong cửa sổ. Gọi nó là "bản gộp" thì sai
            # đúng bằng chiều ngược lại. Chỉ `tcp_ack_window` mới là bản đếm.
            if ev.kind == "tcp_ack_window":
                self._ack_from_aggregate = True
            # Mốc thời gian lấy từ `last_seen` của bản đếm khi có: nó là lần
            # bắt tay GẦN NHẤT trong cửa sổ, đúng thứ `ACK_RETENTION_S` đang
            # đo. Dùng `now()` cho bản đếm sẽ kéo dài tuổi thọ của mọi mục
            # thêm đúng một cửa sổ.
            self._acked_ports.setdefault(src_ip, {})[port] = float(
                ev.data.get("last_seen") or now())

    def _handle_syn(self, ev: Event) -> list[Alert]:
        src_ip = ev.data.get("src_ip")
        port = ev.data.get("dst_port")
        if not src_ip or port is None:
            return []

        now_ts = now()
        events = self._syn_events.setdefault(src_ip, [])
        events[:] = [(p, t) for p, t in events if now_ts - t <= self.window_s]
        events.append((port, now_ts))

        distinct_ports = {p for p, _ in events}
        if len(distinct_ports) <= self.port_threshold:
            return []

        acked = set(self._acked_ports.get(src_ip, {}))
        is_connect_scan = bool(acked & distinct_ports)
        scan_type_key = "connect" if is_connect_scan else "syn"
        scan_type = (
            "connect-scan (handshake hoàn tất)"
            if is_connect_scan
            else "SYN-scan (half-open)"
        )

        return [
            Alert(
                ts=now_ts,
                rule_id="SCAN_PORTSCAN",
                severity="warning",
                title=f"Có port scan nhắm vào máy bạn từ {src_ip}",
                detail=(
                    f"{len(distinct_ports)} port khác nhau bị dò trong "
                    f"{self.window_s:.0f}s — {scan_type}."
                ),
                subject=src_ip,
                evidence={
                    "src_ip": src_ip,
                    "ports": sorted(distinct_ports),
                    "scan_type_key": scan_type_key,
                    "window_s": int(self.window_s),
                    # Nói rõ kết luận "connect-scan" dựa trên cái gì. Từ Phase
                    # 2, ACK đến dưới dạng BẢN ĐẾM theo cửa sổ chứ không phải
                    # gói tin lưu lại — một bằng chứng ghi là "đã thấy gói tin"
                    # trong khi thứ thật sự có là một bộ đếm thì đó là bịa.
                    "ack_source": "aggregate_window" if self._ack_from_aggregate
                                  else "packet",
                    "acked_ports_matched": sorted(acked & distinct_ports),
                },
                playbook=["block_ip", "start_capture"],
            )
        ]
