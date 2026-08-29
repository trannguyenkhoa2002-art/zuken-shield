"""Sniff SYN/ACK tới máy mình để phát hiện port scan (KE-HOACH-SHIELD.md mục 2.3).

Chỉ mô tả sự thật: "thấy SYN tới cổng X từ IP Y", "thấy ACK hoàn tất
handshake từ Y". Detector (portscan.py) mới quyết định đó có phải scan không
và phân biệt SYN-scan (half-open, không ACK) với connect-scan (có ACK).

Hai thay đổi ở Phase 2, cả hai đều xuất phát từ đo đạc trên dữ liệu thật:

1. **Phân loại gói chạy trong thread sniff, có trần tốc độ.** Trước đây
   `on_packet` gọi `run_coroutine_threadsafe` cho MỖI gói tin, không trần,
   không đếm. Một cơn SYN flood — đúng thứ `SCAN_PORTSCAN` sinh ra để phát
   hiện — dồn future không giới hạn vào event loop. Nay gói được phân loại và
   lọc TRƯỚC khi lên lịch bất cứ thứ gì.

2. **`tcp_ack` thành bản đếm theo cửa sổ, không còn lưu từng gói.** Nó từng là
   41,02% toàn bộ telemetry (634.394/1.546.572 event trong 16,5 ngày) để trả
   lời một câu hỏi nhị phân trên 7.981 cặp (ip, port). Cửa sổ 10 giây giảm còn
   41.705 dòng — 93,4% — không mất thông tin nào detector thực sự dùng.

   `tcp_syn` KHÔNG gộp, và đó là lựa chọn có đo: nó chỉ chiếm 0,19% khối lượng
   (2.914 event), còn gộp nó lại sẽ làm chậm phát hiện scan đúng bằng độ dài
   cửa sổ. Gộp thứ rẻ và làm chậm thứ quan trọng là đổi sai chiều. Khoá gộp
   `(src_ip, dst_port)` giống hệt nhau cho cả hai loại, nên quan hệ SYN↔ACK mà
   detector dùng vẫn nguyên vẹn.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
import time

from shield.agent.bus import Bus
from shield.agent.collectors.flowagg import FlowAggregator
from shield.agent.collectors.ratelimit import RateLimiter
from shield.common.models import Event, now

logger = logging.getLogger("shield.conn_watch")

BPF_FILTER = "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) != 0)"

# Trần theo giây, áp TRƯỚC khi lên lịch lên event loop.
#
# SYN cao hơn ACK vì SYN mới là tín hiệu: một lần quét 1000 cổng phải được
# nhìn thấy đủ để vượt ngưỡng 15 cổng của detector. ACK thì chỉ cần đủ để biết
# cặp (ip, port) đó có bắt tay xong hay không — và nó đã được gộp lại.
RATE_LIMIT_PER_S = {"tcp_syn": 2000, "tcp_ack": 2000}

# Cửa sổ gộp ACK. Độ dài này KHÔNG ảnh hưởng độ trễ phát hiện: tín hiệu mà
# detector dùng đi ra ngay ở tầng 1 (`tcp_ack_seen`), cửa sổ chỉ quyết định
# bản đếm khối lượng đến muộn bao lâu — mà không ai cần nó gấp.
# Đo trên dữ liệu thật: 10s giảm 89,4%, 60s giảm 94,7%.
ACK_BUCKET_S = 60.0
# Đo trên dữ liệu thật với cửa sổ 60 giây: trung vị 6 khoá, p99 121, đỉnh 382.
# 4096 là chỗ dư rộng cho một đợt quét thật, và vẫn là một con số chặn được.
ACK_MAX_KEYS = 4096
# Chu kỳ đẩy bản đếm đã đóng ra bus.
FLUSH_INTERVAL_S = 2.0

# Chu kỳ dò lại IP máy mình — vừa để tự phục hồi nếu lúc khởi động chưa có IP
# (mạng lab kiểm thử cô lập, chưa lên DHCP...), vừa để bắt IP mới nếu DHCP
# renew đổi IP giữa chừng, không cần restart agent.
REFRESH_INTERVAL_S = 300


def local_ips() -> set[str]:
    """IP của máy mình — chỉ báo scan nhắm vào các IP này, không phải máy khác.

    Đọc trực tiếp từ `ip -4 -o addr show` — liệt kê MỌI IPv4 non-loopback trên
    MỌI interface, không cần route ra Internet. Trước đây suy ra IP bằng cách
    "connect" UDP giả tới 8.8.8.8, hỏng hoàn toàn trong mạng lab kiểm thử cô
    lập không có Internet, và chỉ thấy được 1 IP (interface dùng để ra ngoài)
    — bỏ sót scan nhắm vào IP khác trên máy nhiều interface (Wi-Fi + Ethernet
    + VPN + Docker, phổ biến ở laptop)."""
    ips: set[str] = set()
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines():
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", line)
            if m and not m.group(1).startswith("127."):
                ips.add(m.group(1))
    except Exception:
        logger.exception("Không liệt kê được IP máy mình qua 'ip addr show'")
    return ips


# `sniff_loop` và `classify` ĐÃ CHUYỂN sang `shield-packet-collector`
# (`packet_helper/sniffers.py`): cả hai bóc lớp scapy, nên chúng thuộc về phía
# có scapy. Phần gộp luồng dưới đây thuần Python và ở lại lõi — nó nhận Event
# `tcp_syn`/`tcp_ack` qua `packet_ingest`, không phân biệt được chúng đến từ
# vòng sniff cũ hay từ helper.

async def _flush_loop(event_bus: Bus, aggregator: FlowAggregator,
                      limiter: RateLimiter, store=None) -> None:
    """Đẩy các cửa sổ đã đóng ra bus và báo sức khoẻ.

    Chỉ đụng dict trong bộ nhớ, không I/O, và số khoá có trần cứng — nên vòng
    này không bao giờ giữ event loop lâu hơn `max_keys` phép gán.
    """
    last_report = 0.0
    while True:
        await asyncio.sleep(FLUSH_INTERVAL_S)
        at = now()
        for kind, data in aggregator.drain(at):
            await event_bus.publish(Event(ts=data["last_seen"], source="conn_watch",
                                          kind=kind, data=data))
        if store is None or at - last_report < 60:
            continue
        last_report = at
        stats = aggregator.stats()
        parts = [f"bản đếm ACK: {stats['live_keys']}/{stats['max_keys']} khoá sống, "
                 f"đỉnh {stats['peak_keys']}, cửa sổ {stats['bucket_s']:.0f}s"]
        if stats["overflow"]:
            parts.append(f"BỎ {stats['overflow']} gói do tràn trần khoá")
        summary = limiter.drop_summary()
        if summary:
            parts.append(summary)
        # Hai loại mất mát KHÁC NHAU, và chỉ một trong hai là bất thường:
        #
        # - Tràn trần khoá của bản đếm: mất hẳn một cặp (ip, port) khỏi tầm
        #   nhìn. Đó là mất TÍN HIỆU, và nó không được báo là khoẻ mạnh.
        # - Chạm trần tốc độ: gói bị bỏ, nhưng cặp (ip, port) vẫn được ghi
        #   nhận qua những gói khác. Bình thường trong một chớp lưu lượng, và
        #   chính lượt quét của Shield cũng tạo ra nó.
        #
        # Nên chỉ hỏi: có đang mất dữ liệu ngay bây giờ không.
        healthy = not stats["overflow"] and not limiter.losing_data_since_last_check()
        # CHỈ số bỏ do trần tốc độ. Tràn trần khoá của bản đếm là mất một
        # KHOÁ gộp chứ không phải một event — đơn vị khác, cộng chung sẽ ra một
        # con số vô nghĩa. Nó ở lại `detail`, nơi nó đã được nói rõ.
        store.set_collector_health("conn_watch", "scapy+aggregate", healthy,
                                   "; ".join(parts),
                                   dropped_events=limiter.total_dropped())


async def aggregate_loop(event_bus: Bus, store=None) -> None:
    """Nghe `tcp_ack` trên bus -> gộp luồng -> phát bản tóm tắt cửa sổ.

    Trước đây bản đếm được nạp thẳng từ `on_packet` của scapy. Giờ nguồn là
    Event do `packet_ingest` phát ra, nên phần gộp này không còn biết gì về gói
    tin — và đó chính là điều làm nó ở lại được trong lõi Apache-2.0.

    Ngữ nghĩa Event phát ra KHÔNG đổi: cùng `source`, cùng `kind`, cùng khoá
    trong `data`, nên detector phía sau không phân biệt được nguồn.
    """
    aggregator = FlowAggregator()
    limiter = RateLimiter(RATE_LIMIT_PER_S)
    flusher = asyncio.create_task(_flush_loop(event_bus, aggregator, limiter, store))
    queue = event_bus.subscribe()
    try:
        while True:
            event = await queue.get()
            if getattr(event, "source", "") != "conn_watch":
                continue
            kind = getattr(event, "kind", "")
            if kind != "tcp_ack":
                # `tcp_syn` đi thẳng tới detector quét cổng; chỉ ACK mới cần gộp.
                continue
            if not limiter.allow(kind, event.ts):
                continue
            data = event.data or {}
            src_ip, dst_port = data.get("src_ip"), data.get("dst_port")
            if not src_ip or not isinstance(dst_port, int):
                continue
            aggregator.add(kind, str(src_ip), int(dst_port), event.ts)
    finally:
        flusher.cancel()
        event_bus.unsubscribe(queue)
