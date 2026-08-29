"""Gộp gói tin tần suất cao thành bản đếm theo cửa sổ, trong bộ nhớ có trần.

Vì sao tồn tại, đo trên dữ liệu thật (1.546.572 event / 16,5 ngày):

    tcp_ack   634.394 event   41,02% TOÀN BỘ telemetry của Shield

Và giá trị điều tra của một dòng `tcp_ack` gần bằng không. Nó không vào
evidence graph, nó không mang PID, nó chỉ có `src_ip` + `dst_port`. Chỗ duy
nhất đọc nó là `PortscanDetector._handle_ack`, và chỗ đó chỉ ghi nhớ *"cặp
(ip, port) này đã từng bắt tay xong"* để phân loại scan là `connect` hay `syn`.

Nói cách khác: 634 nghìn dòng để trả lời một câu hỏi nhị phân trên 7.981 cặp
khác nhau. Gộp theo cửa sổ 10 giây giảm còn 41.705 dòng — **93,4%** — mà
không mất một bit thông tin nào mà detector thực sự dùng.

HAI TẦNG, và đây là điểm quan trọng nhất của thiết kế.

Bản gộp đầu tiên chỉ phát khi cửa sổ ĐÓNG. Phát lại toàn bộ 637.548 gói thật
kèm bốn cuộc quét chèn vào cho thấy nó làm HỎNG phân loại: một connect-scan
nhanh bị gán nhãn `syn`, vì ACK còn nằm trong bộ đếm khi alert đã phát đi.
Cụ thể, `198.51.100.5` (40 cổng trong 1 giây, có bắt tay đầy đủ):

    trước gộp:  connect        sau gộp một tầng:  syn

Cái giá của việc giảm khối lượng không được là nói sai chuyện gì đã xảy ra.
Nên:

- **Tầng 1 — `tcp_ack_seen`, phát NGAY** khi một khoá xuất hiện lần đầu trong
  cửa sổ. Đây là một gói tin THẬT đã quan sát được, không phải bản gộp, và nó
  mang đúng tín hiệu mà `PortscanDetector` dùng: cặp (ip, port) này đã bắt tay
  xong. Độ trễ phát hiện vì thế KHÔNG đổi một chút nào.
- **Tầng 2 — `tcp_ack_window`, phát khi cửa sổ đóng**, và CHỈ khi khoá đó có
  từ 2 gói trở lên. Khoá chỉ có đúng một gói thì tầng 1 đã nói hết rồi.

Đếm tổng số gói của một khoá trong một cửa sổ: lấy `count` của bản ghi
`tcp_ack_window` nếu có; nếu không có thì là 1.

Đo trên dữ liệu thật với cửa sổ 60 giây: 634.394 gói -> 33.894 dòng, giảm
**94,7%**, và kết quả detector giống hệt trước tới từng cổng.

Nguyên tắc:

- Khoá gộp là TẤT ĐỊNH: `(kind, src_ip, dst_port, chỉ_số_cửa_sổ)`. Cùng dòng
  gói tin cho ra cùng tập bản đếm, nên so được giữa hai lần chạy.
- Cửa sổ CỐ ĐỊNH theo đồng hồ (`floor(ts / bucket_s)`), không phải cửa sổ trôi
  theo gói đầu tiên — cửa sổ trôi làm kết quả phụ thuộc thứ tự tới.
- Trần CỨNG số khoá đang sống. Vượt trần thì BỎ và ĐẾM, không phình bộ nhớ.
  Nguồn dữ liệu ở đây do kẻ tấn công điều khiển tốc độ.
- Bản đếm giữ đúng thứ detector cần: `count`, `first_seen`, `last_seen`.
  KHÔNG giữ gói thô. Alert sinh ra từ bản đếm phải nói rõ nó đến từ bản đếm.
"""

from __future__ import annotations


class FlowAggregator:
    """Bản đếm theo `(kind, src_ip, dst_port)` trong cửa sổ thời gian cố định.

    `add()` gọi từ thread sniff; `drain()` gọi từ event loop. Cả hai chỉ đụng
    dict trong bộ nhớ, không I/O — nên `drain()` không bao giờ chặn event loop
    lâu hơn số khoá đang sống, mà số đó có trần cứng.
    """

    def __init__(self, bucket_s: float = 10.0, max_keys: int = 4096) -> None:
        if bucket_s <= 0:
            raise ValueError("bucket_s phải dương")
        if max_keys < 1:
            raise ValueError("max_keys phải dương")
        self.bucket_s = float(bucket_s)
        self.max_keys = int(max_keys)
        self._buckets: dict[tuple, dict] = {}
        # Số lần một gói bị bỏ vì đã chạm trần khoá. Bỏ mà không đếm là mất dữ
        # liệu trong im lặng, và nó trông y hệt như "mạng yên tĩnh".
        self.overflow = 0
        self.peak_keys = 0

    def add(self, kind: str, src_ip: str, dst_port: int,
            at: float) -> tuple[str, dict] | None:
        """Ghi nhận một gói.

        Trả về bản ghi TẦNG 1 cần phát ngay khi đây là lần đầu khoá này xuất
        hiện trong cửa sổ; `None` cho mọi gói sau đó (chúng chỉ tăng bộ đếm) và
        cho gói bị bỏ vì chạm trần.
        """
        window = int(at // self.bucket_s)
        key = (kind, src_ip, int(dst_port), window)
        entry = self._buckets.get(key)
        if entry is None:
            if len(self._buckets) >= self.max_keys:
                self.overflow += 1
                return None
            self._buckets[key] = {"count": 1, "first_seen": at, "last_seen": at}
            if len(self._buckets) > self.peak_keys:
                self.peak_keys = len(self._buckets)
            # Một gói tin thật, quan sát được. KHÔNG gắn cờ `aggregate`: nó
            # không phải bản gộp, và nói nó là bản gộp cũng sai như chiều ngược
            # lại.
            return (f"{kind}_seen", {
                "src_ip": src_ip, "dst_port": int(dst_port),
                "window_s": self.bucket_s, "window_start": window * self.bucket_s,
            })
        entry["count"] += 1
        # `first_seen` không lùi: gói tới không đúng thứ tự vẫn cho cùng kết quả.
        if at < entry["first_seen"]:
            entry["first_seen"] = at
        if at > entry["last_seen"]:
            entry["last_seen"] = at
        return None

    def drain(self, at: float) -> list[tuple[str, dict]]:
        """Lấy ra các cửa sổ ĐÃ ĐÓNG. Cửa sổ đang chạy được giữ lại.

        Hết hạn là chính cơ chế này: một khoá chỉ sống tới khi cửa sổ của nó
        đóng, nên không có mục nào nằm lại vô thời hạn.

        Thứ tự trả về cố định (theo khoá đã sắp) để hai lần chạy trên cùng dòng
        gói tin cho ra cùng dãy event.
        """
        current = int(at // self.bucket_s)
        ready = sorted(key for key in self._buckets if key[3] < current)
        out: list[tuple[str, dict]] = []
        for key in ready:
            kind, src_ip, dst_port, window = key
            entry = self._buckets.pop(key)
            # Khoá chỉ có MỘT gói thì tầng 1 đã nói hết. Phát thêm một bản đếm
            # `count: 1` chỉ là nhân đôi số dòng để không thêm thông tin nào.
            if entry["count"] < 2:
                continue
            out.append((f"{kind}_window", {
                "src_ip": src_ip, "dst_port": dst_port,
                # Nói thẳng đây là bản đếm, không phải một gói tin quan sát
                # được. Một alert trích dẫn "gói tin" mà thực ra chỉ có bản đếm
                # là bịa bằng chứng.
                "aggregate": True,
                # `count` là TỔNG của cả cửa sổ, gồm cả gói đã báo ở tầng 1.
                # Cộng dồn khối lượng: lấy `count` ở đây nếu có bản ghi này,
                # ngược lại khoá đó có đúng 1 gói.
                "count": entry["count"],
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "window_s": self.bucket_s,
                "window_start": window * self.bucket_s,
            }))
        return out

    def stats(self) -> dict:
        return {"live_keys": len(self._buckets), "peak_keys": self.peak_keys,
                "overflow": self.overflow, "max_keys": self.max_keys,
                "bucket_s": self.bucket_s}
