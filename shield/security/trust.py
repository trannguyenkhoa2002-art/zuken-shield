"""Hai mức tin cậy cho log đi vào Shield (KE-HOACH-SHIELD-1.1.md mục A2).

Từ 1.1, Shield nhận log từ máy khác. Có hai đường vào, và chúng KHÔNG ngang
hàng nhau:

- `authenticated` — log của chính máy này, hoặc từ Shield Probe đã ghi danh
  bằng chứng chỉ mTLS. Có danh tính mật mã, biết chắc ai gửi.
- `unauthenticated` — syslog thô từ router/camera/switch. Giao thức syslog
  không có xác thực: bất kỳ ai trong LAN cũng gửi được một gói UDP khai mình
  là router. Hostname trong gói là do NGƯỜI GỬI TỰ KHAI.

Nếu trộn hai thứ này làm một, hậu quả cụ thể:

1. Kẻ tấn công bơm log giả vào `forensic_ledger` -> toàn bộ chuỗi bằng chứng
   mất giá trị, kể cả những dòng thật.
2. Bơm alert `critical` giả -> người dùng học được rằng cảnh báo của Shield
   là nhiễu, rồi bỏ qua cả cảnh báo thật.
3. Bơm hành vi "bình thường" giả -> đầu độc baseline, khiến hành vi tấn công
   thật trở thành "đã thấy rồi, không đáng báo".

Ba hàm dưới đây là chỗ duy nhất áp ba ranh giới đó.
"""

from __future__ import annotations

from dataclasses import replace

from shield.common.models import Alert, Event

AUTHENTICATED = "authenticated"
UNAUTHENTICATED = "unauthenticated"

# Trần severity cho nguồn không xác thực. Không phải "bỏ qua" — log router vẫn
# hữu ích — mà là "không bao giờ được tự mình leo lên mức critical".
MAX_UNAUTHENTICATED_SEVERITY = "warning"
_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


def event_trust(event: Event) -> str:
    return UNAUTHENTICATED if event.data.get("trust") == UNAUTHENTICATED else AUTHENTICATED


def is_authenticated(event: Event) -> bool:
    return event_trust(event) == AUTHENTICATED


def may_enter_forensic_ledger(alert: Alert) -> bool:
    """Ledger là chuỗi hash chống sửa. Chỉ nhận thứ có danh tính."""
    return alert.evidence.get("trust") != UNAUTHENTICATED


def may_train_baseline(event: Event) -> bool:
    """Baseline học "cái gì là bình thường". Nguồn giả mạo được thì không
    được phép dạy nó."""
    return is_authenticated(event) and not event.data.get("synthetic")


def stamp_alert(alert: Alert, event: Event) -> Alert:
    """Gắn nguồn gốc vào alert và hạ trần severity nếu nguồn không xác thực.

    Gọi ở đúng một chỗ (run_event_consumer) ngay sau khi detector sinh alert:
    detector không cần biết event đến từ đâu, và cũng không nên biết — nhiệm
    vụ của nó là phát hiện, không phải phân xử tin cậy.
    """
    trust = event_trust(event)
    origin = str(event.data.get("origin", "local"))
    evidence = dict(alert.evidence)
    evidence.setdefault("trust", trust)
    evidence.setdefault("origin", origin)
    # THAM CHIẾU BẰNG CHỨNG: `events.event_id` của event đã trực tiếp sinh ra
    # alert này. Không phải id mới — đúng khoá đã có trong bảng `events`.
    #
    # Gắn Ở ĐÂY chứ không ở từng detector là có chủ ý: đây là chỗ duy nhất mọi
    # alert do detector sinh ra đi qua, và detector không cần biết gì về lưu
    # trữ. Rải việc này ra tám detector thì tám lần có cơ hội quên.
    #
    # `setdefault`: detector nào tự biết chính xác hơn (ví dụ giữ được nhiều
    # event nguồn) thì giữ giá trị của nó.
    #
    # Rỗng thì KHÔNG gắn. Một alert không truy được về event nào phải nhìn ra
    # được là như vậy; gắn một chuỗi rỗng làm nó trông như có nguồn.
    if event.event_id:
        evidence.setdefault("event_id", event.event_id)

    severity = alert.severity
    if trust == UNAUTHENTICATED and _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK[MAX_UNAUTHENTICATED_SEVERITY]:
        evidence["severity_capped_from"] = severity
        evidence["severity_capped_reason"] = (
            "source is unauthenticated syslog; anyone on the LAN can forge it"
        )
        severity = MAX_UNAUTHENTICATED_SEVERITY

    return replace(alert, severity=severity, evidence=evidence)
