"""4 detector chống MITM/nghe lén trên LAN nhà + 1 bonus rẻ tiền
(KE-HOACH-SHIELD.md mục 2.1 — ưu tiên số 1 theo nhu cầu ban đầu).

Mọi rule ở đây dựa vào **baseline** (bảng `baseline` trong Store): MAC gateway
"sạch" được người dùng xác nhận lúc mạng chắc chắn an toàn. Nếu chưa có
baseline, `MITM_GATEWAY_MAC_CHANGED` không hoạt động được — ghi log 1 lần,
không silently fail vô thời hạn.

Input: Event từ collector `arp_sniffer` (kind: arp_reply | arp_gratuitous |
dhcp_offer | icmp_redirect). Output: list[Alert] (rỗng nếu không có gì đáng báo).
"""

from __future__ import annotations

import logging

from shield.agent.store import Store
from shield.common.models import Alert, Event, now

logger = logging.getLogger("shield.detectors.mitm")

ARP_CONFLICT_WINDOW_S = 60.0
GRATUITOUS_ARP_WINDOW_S = 1.0
GRATUITOUS_ARP_THRESHOLD = 20  # gói/giây — chữ ký arpspoof/ettercap

# Dọn key rỗng trong _ip_claims mỗi 5 phút thay vì mỗi event — _ip_claims chỉ
# được lọc (theo cửa sổ thời gian) khi CHÍNH IP đó có event mới; IP ngừng gửi
# ARP (thiết bị rời mạng) để lại key với list cũ nằm mãi trong dict, rò rỉ bộ
# nhớ chậm — đáng chú ý khi kiểm thử liên tục nhiều tuần với nhiều IP lạ.
CLEANUP_INTERVAL_S = 300.0

BASELINE_GW_IP = "gateway_ip"
BASELINE_GW_MAC = "gateway_mac"
BASELINE_DHCP_IP = "dhcp_server_ip"


class MitmDetector:
    def __init__(self, store: Store) -> None:
        self.store = store
        # State trong RAM, cửa sổ thời gian ngắn — không cần bền qua restart.
        self._ip_claims: dict[str, list[tuple[str, float]]] = {}
        self._ip6_claims: dict[str, list[tuple[str, float]]] = {}  # tương đương _ip_claims, cho NDP/IPv6
        self._gratuitous_ts: list[float] = []
        self._warned_no_baseline = False
        self._last_cleanup = 0.0

    def _cleanup_stale(self, now_ts: float) -> None:
        if now_ts - self._last_cleanup < CLEANUP_INTERVAL_S:
            return
        self._last_cleanup = now_ts
        for claims_dict, window in (
            (self._ip_claims, ARP_CONFLICT_WINDOW_S),
            (self._ip6_claims, ARP_CONFLICT_WINDOW_S),
        ):
            stale_keys = [
                k for k, claims in claims_dict.items()
                if not any(now_ts - t <= window for _, t in claims)
            ]
            for k in stale_keys:
                del claims_dict[k]

    def handle_event(self, ev: Event) -> list[Alert]:
        self._cleanup_stale(now())
        if ev.kind == "arp_reply":
            return self._handle_arp_reply(ev)
        if ev.kind == "arp_gratuitous":
            return self._handle_gratuitous_arp(ev)
        if ev.kind == "dhcp_offer":
            return self._handle_dhcp_offer(ev)
        if ev.kind == "icmp_redirect":
            return self._handle_icmp_redirect(ev)
        if ev.kind == "ndp_advertisement":
            return self._handle_ndp_advertisement(ev)
        return []

    # --- MITM_GATEWAY_MAC_CHANGED + MITM_ARP_CONFLICT ---

    def _handle_arp_reply(self, ev: Event) -> list[Alert]:
        ip = ev.data.get("ip")
        mac = ev.data.get("mac")
        if not ip or not mac:
            return []
        mac = mac.lower()
        alerts: list[Alert] = []

        gw_ip = self.store.get_baseline(BASELINE_GW_IP)
        gw_mac = self.store.get_baseline(BASELINE_GW_MAC)
        if gw_ip is None or gw_mac is None:
            if not self._warned_no_baseline:
                logger.warning(
                    "Chưa có baseline gateway — MITM_GATEWAY_MAC_CHANGED không "
                    "hoạt động. Gửi lệnh set_gateway_baseline để thiết lập."
                )
                self._warned_no_baseline = True
        elif ip == gw_ip and mac != gw_mac.lower():
            alerts.append(
                Alert(
                    ts=now(),
                    rule_id="MITM_GATEWAY_MAC_CHANGED",
                    severity="critical",
                    title="MAC của gateway đã đổi — nghi ngờ ARP spoofing",
                    detail=(
                        f"Gateway {gw_ip} trước đây có MAC {gw_mac}, giờ trả lời "
                        f"bằng MAC {mac}. Đây là dấu hiệu MITM rõ nhất trên LAN nhà."
                    ),
                    subject=gw_ip,
                    evidence={"gateway_ip": gw_ip, "baseline_mac": gw_mac, "observed_mac": mac},
                    playbook=["pin_gateway_arp", "start_capture", "snapshot_state"],
                )
            )

        alerts.extend(self._check_arp_conflict(ip, mac))
        return alerts

    def _check_arp_conflict(self, ip: str, mac: str) -> list[Alert]:
        """Một IP được claim bởi >1 MAC trong cửa sổ 60s -> nghi ngờ MITM."""
        now_ts = now()
        claims = self._ip_claims.setdefault(ip, [])
        claims[:] = [(m, t) for m, t in claims if now_ts - t <= ARP_CONFLICT_WINDOW_S]
        claims.append((mac, now_ts))

        distinct_macs = {m for m, _ in claims}
        if len(distinct_macs) <= 1:
            return []

        return [
            Alert(
                ts=now_ts,
                rule_id="MITM_ARP_CONFLICT",
                severity="critical",
                title=f"IP {ip} bị nhiều MAC khác nhau claim",
                detail=(
                    f"Trong {ARP_CONFLICT_WINDOW_S:.0f}s qua, IP {ip} được claim bởi "
                    f"{len(distinct_macs)} MAC khác nhau: {sorted(distinct_macs)}."
                ),
                subject=ip,
                evidence={
                    "ip": ip,
                    "macs": sorted(distinct_macs),
                    "window_s": int(ARP_CONFLICT_WINDOW_S),
                },
                playbook=["start_capture", "snapshot_state"],
            )
        ]

    # --- MITM_NDP_CONFLICT (IPv6 — tương đương MITM_ARP_CONFLICT) ---

    def _handle_ndp_advertisement(self, ev: Event) -> list[Alert]:
        ip6 = ev.data.get("ip")
        mac = ev.data.get("mac")
        if not ip6 or not mac:
            return []
        mac = mac.lower()

        now_ts = now()
        claims = self._ip6_claims.setdefault(ip6, [])
        claims[:] = [(m, t) for m, t in claims if now_ts - t <= ARP_CONFLICT_WINDOW_S]
        claims.append((mac, now_ts))

        distinct_macs = {m for m, _ in claims}
        if len(distinct_macs) <= 1:
            return []

        return [
            Alert(
                ts=now_ts,
                rule_id="MITM_NDP_CONFLICT",
                severity="critical",
                title=f"Địa chỉ IPv6 {ip6} bị nhiều MAC khác nhau claim",
                detail=(
                    f"Trong {ARP_CONFLICT_WINDOW_S:.0f}s qua, Neighbor Advertisement cho "
                    f"{ip6} tới từ {len(distinct_macs)} MAC khác nhau: {sorted(distinct_macs)}. "
                    "Đây là dấu hiệu MITM trên IPv6 (tương đương ARP conflict ở IPv4)."
                ),
                subject=ip6,
                evidence={
                    "ip6": ip6,
                    "macs": sorted(distinct_macs),
                    "window_s": int(ARP_CONFLICT_WINDOW_S),
                },
                playbook=["start_capture", "snapshot_state"],
            )
        ]

    # --- NET_GRATUITOUS_ARP_FLOOD (bonus, chữ ký arpspoof/ettercap) ---

    def _handle_gratuitous_arp(self, ev: Event) -> list[Alert]:
        mac = (ev.data.get("mac") or "unknown").lower()
        now_ts = now()
        self._gratuitous_ts.append(now_ts)
        self._gratuitous_ts[:] = [
            t for t in self._gratuitous_ts if now_ts - t <= GRATUITOUS_ARP_WINDOW_S
        ]
        if len(self._gratuitous_ts) <= GRATUITOUS_ARP_THRESHOLD:
            return []

        return [
            Alert(
                ts=now_ts,
                rule_id="NET_GRATUITOUS_ARP_FLOOD",
                severity="warning",
                title="Có gratuitous ARP bất thường nhiều — nghi arpspoof/ettercap",
                detail=(
                    f"{len(self._gratuitous_ts)} gratuitous ARP/giây, vượt ngưỡng "
                    f"{GRATUITOUS_ARP_THRESHOLD}. Đây là chữ ký của công cụ ARP spoof."
                ),
                subject=mac,
                evidence={
                    "mac": mac,
                    "rate_per_s": len(self._gratuitous_ts),
                    "threshold": GRATUITOUS_ARP_THRESHOLD,
                },
                playbook=["start_capture"],
            )
        ]

    # --- MITM_ROGUE_DHCP ---

    def _handle_dhcp_offer(self, ev: Event) -> list[Alert]:
        server_ip = ev.data.get("server_ip")
        if not server_ip:
            return []

        known = self.store.get_baseline(BASELINE_DHCP_IP)
        if known is None:
            # Học baseline lần đầu thấy — giống baseline gateway, giả định mạng
            # sạch lúc mới bật app. Không alert cho lần học này.
            self.store.set_baseline(BASELINE_DHCP_IP, server_ip)
            logger.info("Đã học baseline DHCP server: %s", server_ip)
            return []

        if server_ip == known:
            return []

        return [
            Alert(
                ts=now(),
                rule_id="MITM_ROGUE_DHCP",
                severity="critical",
                title="Có DHCP server lạ đang phát OFFER",
                detail=(
                    f"DHCP server đã biết là {known}, nhưng vừa thấy OFFER từ "
                    f"{server_ip}. Có thể là rogue DHCP để MITM toàn mạng."
                ),
                subject=server_ip,
                evidence={"known_dhcp": known, "rogue_dhcp": server_ip},
                playbook=["start_capture", "block_ip", "snapshot_state"],
            )
        ]

    # --- MITM_ICMP_REDIRECT ---

    def _handle_icmp_redirect(self, ev: Event) -> list[Alert]:
        src_ip = ev.data.get("src_ip")
        src_ip_display = src_ip or "không rõ"
        return [
            Alert(
                ts=now(),
                rule_id="MITM_ICMP_REDIRECT",
                severity="warning",
                title="Nhận được ICMP Redirect",
                detail=(
                    f"Gói ICMP Redirect từ {src_ip_display}. Mạng nhà bình thường không "
                    "bao giờ cần gói này — chỉ cần thấy là đáng ngờ."
                ),
                subject=src_ip_display,
                evidence={"src_ip": src_ip},
                playbook=["snapshot_state"],
            )
        ]
