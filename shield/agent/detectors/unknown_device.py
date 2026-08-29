"""Rule DEVICE_NEW + gộp MAC ngẫu nhiên (KE-HOACH-SHIELD.md mục 2.2).

Nguyên tắc: detector chỉ đọc Event, không tự gọi lệnh hệ thống. Input là
Event(kind="host_seen") từ collector discovery, output là Alert hoặc None.
"""

from __future__ import annotations

from shield.agent.store import Store
from shield.common.models import Alert, Event, now

# Bit locally-administered = bit thứ 2 của octet đầu tiên (0b10). Các hệ điều
# hành di động (iOS 14+, Android 10+) bật bit này khi random hoá MAC cho mỗi
# mạng Wi-Fi mới -> nếu không gộp lại sẽ đẻ ra hàng chục "thiết bị mới" giả.
RANDOMIZED_MAC_SUBJECT = "randomized-mac-pool"


def is_locally_administered(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b10)


class UnknownDeviceDetector:
    def __init__(self, store: Store) -> None:
        self.store = store

    def handle_event(self, ev: Event) -> list[Alert]:
        if ev.kind != "host_seen":
            return []

        mac = ev.data.get("mac")
        if not mac:
            return []
        mac = mac.lower()
        ip = ev.data.get("ip")

        if self.store.is_trusted(mac):
            self.store.touch_device(mac, ip)
            return []

        is_new, vendor = self.store.upsert_device(
            mac, ip, vendor_hint=ev.data.get("vendor_hint"), observation=ev.data,
        )
        if not is_new:
            return []

        if is_locally_administered(mac):
            return [Alert(
                ts=now(),
                rule_id="DEVICE_MAC_RANDOMIZED",
                severity="info",
                title="Thiết bị dùng MAC ngẫu nhiên (riêng tư)",
                detail=(
                    f"IP {ip} dùng MAC riêng tư (locally-administered) — thường là "
                    "điện thoại iOS/Android. Các MAC dạng này được gộp vào một dòng "
                    "để tránh spam."
                ),
                subject=RANDOMIZED_MAC_SUBJECT,
                evidence={"mac": mac, "ip": ip},
                playbook=[],
            )]

        return [Alert(
            ts=now(),
            rule_id="DEVICE_NEW",
            severity="info",
            title="Thiết bị mới xuất hiện trong mạng",
            detail=f"MAC {mac} ({vendor or 'vendor không rõ'}), IP {ip}",
            subject=mac,
            evidence={"mac": mac, "ip": ip, "vendor": vendor},
            playbook=["trust_device"],
        )]
