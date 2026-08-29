"""Hai kiểu dữ liệu cốt lõi dùng chung giữa agent và UI.

Nguyên tắc (xem KE-HOACH-SHIELD.md mục 1.2):
- collector chỉ mô tả sự thật -> Event.
- detector mới có logic, sinh ra Alert.
- subject + rule_id là khoá dedupe chống spam alert.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from dataclasses import asdict, dataclass, field

# KE-HOACH-SHIELD-2.0.md mục 1.1. Event schema v2 mở rộng THEO HƯỚNG TƯƠNG
# THÍCH NGƯỢC: mọi trường mới nằm ở CUỐI và có giá trị mặc định.
#
# Vị trí không phải chuyện thẩm mỹ. `Event(ts, source, kind, data)` được gọi
# theo vị trí ở hàng trăm chỗ trong collector; chèn một trường vào giữa sẽ
# lặng lẽ dịch mọi tham số đi một nấc — đúng lỗi đã xảy ra khi `min_count`
# được chèn vào giữa `CorrelationRule`, và không test nào bắt được vì mọi
# trường đều nhận được một giá trị trông có vẻ hợp lệ.
EVENT_SCHEMA_VERSION = 2

# Thang tin cậy. So sánh bằng số, không bằng chuỗi: "authenticated" < "local"
# đúng theo thứ tự bảng chữ cái nhưng sai theo ngữ nghĩa.
TRUST_ORDER = {"synthetic": 0, "unauthenticated": 1, "authenticated": 2, "local": 3}


def trust_rank(trust: str) -> int:
    """Bậc tin cậy. Giá trị lạ được coi là YẾU NHẤT, không phải mạnh nhất."""
    return TRUST_ORDER.get(str(trust), 0)


def new_event_id(at: float | None = None) -> str:
    """ID sắp theo thời gian: 12 ký tự hex mili-giây + 20 ký tự hex ngẫu nhiên.

    Sắp theo thời gian có hai lợi ích thật: index trên cột này ghi tuần tự thay
    vì rải khắp cây B, và khi đọc log thô người ta so sánh được hai ID mà không
    cần tra bảng. Phần ngẫu nhiên 80 bit đủ để hai collector chạy song song
    trong cùng một mili-giây không đụng nhau.
    """
    milliseconds = int((time.time() if at is None else at) * 1000) & 0xFFFFFFFFFFFF
    return struct.pack(">Q", milliseconds)[2:].hex() + os.urandom(10).hex()


def content_hash(source: str, kind: str, data: dict) -> str:
    """sha256 của nội dung đã chuẩn hoá — dùng để phát hiện sửa đổi và trùng lặp.

    `sort_keys=True` là bắt buộc: thứ tự khoá trong dict Python phụ thuộc thứ
    tự chèn, nên cùng một sự kiện có thể ra hai hash khác nhau nếu không chuẩn
    hoá — và khi đó hash không phát hiện được gì cả.
    """
    payload = json.dumps({"source": source, "kind": kind, "data": data},
                         sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


@dataclass(frozen=True)
class Event:
    ts: float            # thời điểm SỰ KIỆN xảy ra
    source: str          # "arp_sniffer" | "discovery" | "journal" | "fake_injector" | ...
    kind: str            # "arp_reply" | "host_seen" | "syn_to_closed" | ...
    data: dict = field(default_factory=dict)

    # --- schema v2: thêm ở cuối, đều có mặc định ---

    # Duy nhất toàn hệ thống; rỗng nghĩa là "tự sinh khi khởi tạo".
    event_id: str = ""
    # Thời điểm Shield NHẬN được. Giữ cả hai mốc để phát hiện độ trễ, phát lại
    # và đồng hồ lệch — một event có ts_event trong tương lai, hoặc trễ hàng
    # giờ so với lúc nhận, là tín hiệu điều tra chứ không phải nhiễu.
    ts_ingested: float = 0.0
    origin: str = "local"          # "local" | "probe:<id>" | "syslog:<ip>"
    trust: str = "local"           # xem TRUST_ORDER
    collector_version: str = ""
    content_hash_: str = ""
    signature_status: str = "unsigned"   # verified | unsigned | invalid

    def __post_init__(self) -> None:
        # Frozen dataclass: phải ghi qua object.__setattr__. Sinh ở đây thay vì
        # ở chỗ gọi để KHÔNG event nào lọt vào hệ thống mà thiếu danh tính —
        # một bằng chứng không tham chiếu được thì không phải bằng chứng.
        if not self.event_id:
            object.__setattr__(self, "event_id", new_event_id(self.ts))
        if not self.ts_ingested:
            object.__setattr__(self, "ts_ingested", time.time())
        if not self.content_hash_:
            object.__setattr__(self, "content_hash_", content_hash(self.source, self.kind, self.data))

    @property
    def ts_event(self) -> float:
        """Tên theo schema v2. `ts` giữ nguyên vì hàng trăm chỗ đang dùng."""
        return self.ts

    @property
    def ingest_lag_s(self) -> float:
        """Trễ giữa lúc xảy ra và lúc nhận. Âm nghĩa là đồng hồ nguồn chạy trước."""
        return self.ts_ingested - self.ts

    def evidence_ref(self) -> str:
        return f"event:{self.event_id}"

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["schema_version"] = EVENT_SCHEMA_VERSION
        payload["ts_event"] = self.ts
        payload["integrity"] = {
            "content_hash": payload.pop("content_hash_"),
            "signature_status": payload.pop("signature_status"),
        }
        return payload

    @staticmethod
    def from_dict(d: dict) -> "Event":
        integrity = d.get("integrity") or {}
        return Event(
            ts=d.get("ts", d.get("ts_event", 0.0)),
            source=d["source"],
            kind=d["kind"],
            data=d.get("data", {}),
            event_id=d.get("event_id", ""),
            ts_ingested=d.get("ts_ingested", 0.0),
            origin=d.get("origin", "local"),
            trust=d.get("trust", "local"),
            collector_version=d.get("collector_version", ""),
            content_hash_=integrity.get("content_hash", d.get("content_hash", "")),
            signature_status=integrity.get("signature_status", d.get("signature_status", "unsigned")),
        )


@dataclass(frozen=True)
class Alert:
    ts: float
    rule_id: str         # "MITM_GATEWAY_MAC_CHANGED"
    severity: str        # info | warning | critical
    title: str            # tiếng Việt, ngắn
    detail: str
    subject: str          # MAC hoặc IP — dùng để dedupe
    evidence: dict = field(default_factory=dict)
    playbook: list = field(default_factory=list)  # id các hành động gợi ý
    risk_score: int = 0       # 0..100, được scoring engine tính trước khi lưu
    # SỨC MẠNH BẰNG CHỨNG (0..1), KHÔNG phải xác suất alert này đúng.
    #
    # Trường này từng tên là `confidence`. Người đọc thấy "confidence 0.90" và
    # hiểu "90% khả năng đúng"; thực tế nó có nghĩa "alert này có 5 mẩu bằng
    # chứng và đã lặp lại". Mục 3.4 của kế hoạch 2.0 cấm đúng chuyện đó.
    #
    # Độ chính xác THẬT của một detector nằm ở `detector_calibration` và chỉ
    # tồn tại khi có NGƯỜI dán nhãn. Hai con số này không thay thế nhau.
    evidence_strength: float = 0.5
    policy_action: str = "alert"  # quyết định minh bạch; AI không được ghi field này
    # THAM CHIẾU CHÍNH DANH tới dòng trong bảng `alerts` (`alerts.id`), do
    # `Store.insert_alert` điền vào. KHÔNG phải một hệ định danh mới: đây đúng
    # là khoá chính đã có, được mang theo thay vì phải tra lại.
    #
    # Vì sao phải mang theo: `insert_alert` gộp trùng bằng cách CẬP NHẬT `ts`
    # của dòng cũ. Nên cặp (rule_id, ts) — thứ mà `incident_alerts` từng dùng —
    # trỏ tới một thời điểm không còn tồn tại trong bảng `alerts` ngay sau lần
    # gộp trùng đầu tiên. Tra ngược theo cặp đó là phỏng đoán, không phải tham
    # chiếu.
    #
    # 0 nghĩa là "alert này chưa được lưu" (đang trên đường ống, hoặc dựng
    # trong test). Không bao giờ dùng 0 làm khoá tra cứu.
    alert_id: int = 0
    # Cửa sổ chống trùng RIÊNG của alert này, giây. 0 = dùng mặc định của chỗ
    # gọi (300 giây).
    #
    # Có mặt vì một vài phát hiện có nhịp khác hẳn: quan sát lúc khởi động
    # được phát lại MỖI lần agent chạy, nên với cửa sổ 300 giây thì mỗi lần
    # khởi động lại là một hàng alert mới cho đúng một sự việc không đổi.
    # Cơ chế chống trùng chính danh — `(subject, rule_id)` tra thẳng bảng
    # `alerts`, nên sống qua restart — đã đủ sức diễn đạt điều đó; thứ thiếu
    # chỉ là cách để detector nói ra nhịp của mình.
    dedupe_window_s: float = 0.0

    @property
    def confidence(self) -> float:
        """Tên cũ, chỉ đọc.

        Giữ lại để mã và dữ liệu cũ không hỏng cùng lúc với việc đổi ý nghĩa.
        Đổi tên VÀ đổi ngữ nghĩa trong một lượt là cách chắc chắn để không ai
        biết chỗ nào đã sửa.
        """
        return self.evidence_strength

    def to_dict(self) -> dict:
        payload = asdict(self)
        # Gương cho bản cũ: một bản Shield cũ đọc alert này vẫn thấy đúng số.
        # Sẽ bỏ khi không còn bản nào đọc khoá đó.
        payload["confidence"] = self.evidence_strength
        return payload

    @staticmethod
    def from_dict(d: dict) -> "Alert":
        return Alert(
            ts=d["ts"],
            rule_id=d["rule_id"],
            severity=d["severity"],
            title=d["title"],
            detail=d["detail"],
            subject=d["subject"],
            evidence=d.get("evidence", {}),
            playbook=d.get("playbook", []),
            risk_score=int(d.get("risk_score", 0)),
            # Nhận cả tên mới lẫn tên cũ: dữ liệu đã lưu trước 2.0 dùng tên cũ,
            # và một bản ghi cũ không đọc được là một bản ghi mất.
            evidence_strength=float(
                d.get("evidence_strength", d.get("confidence", 0.5))),
            policy_action=d.get("policy_action", "alert"),
            alert_id=int(d.get("alert_id", 0) or 0),
            dedupe_window_s=float(d.get("dedupe_window_s", 0.0) or 0.0),
        )


def now() -> float:
    return time.time()
