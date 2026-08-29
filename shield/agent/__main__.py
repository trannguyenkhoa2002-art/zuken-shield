"""Entrypoint agent — chạy: python -m shield.agent [cờ]

- --inject-fake-events: verify đường ống Event/Alert -> SQLite -> IPC -> UI
  (giai đoạn 0, không cần root, không cần arp-scan/nmap).
- --discover: bật collector arp-scan (60s) + nmap -sn (15 phút), rule
  DEVICE_NEW/DEVICE_MAC_RANDOMIZED (giai đoạn 1). Cần root.
- --mitm: bật arp_sniffer (scapy) + 4 detector chống MITM + wizard baseline
  gateway qua IPC (giai đoạn 2). Cần root + `pip install scapy`.
- --portscan: bật conn_watch (sniff SYN/ACK tới máy mình) + rule
  SCAN_PORTSCAN (giai đoạn 3). Cần root + scapy. Lệnh watch_device/
  unwatch_device (theo dõi lưu lượng 1 host, tcpdump + đồ thị) luôn khả dụng
  qua IPC, không cần cờ này.
- --journal: bật journalctl -f + rule LOCAL_SSH_BRUTEFORCE/LOCAL_SUDO_FAIL/
  LOCAL_NEW_USB/LOCAL_PROMISC_MODE (giai đoạn 4). Alert critical tự thông
  báo qua notify-send + Telegram (cần env SHIELD_TELEGRAM_TOKEN/CHAT_ID).

Dev (không cần systemd):
    sudo python -m shield.agent --discover --mitm --portscan --journal  # cần root
    python -m shield.agent --inject-fake-events                          # không cần root

Production (sau giai đoạn 5): chạy dưới systemd, xem systemd/shield-agent.service.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import ipaddress
import json
import logging
import os
import random
import re
import sqlite3
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from shield.agent import actions, dns_audit, evasion, notifier, router_backends, tarpit
from shield.agent.bus import Bus
from shield.agent.collectors import conn_watch, endpoint, journal, kernel, packet_ingest
from shield.agent.collectors.log_ingest import DEFAULT_RATE_PER_PROBE, LogIngestServer
from shield.agent.collectors.syslog_server import SyslogCollector
from shield.agent.collectors.discovery import (
    detect_gateway_ip,
    detect_gateway_mac,
    detect_interface,
    detect_subnet,
    discovery_loop,
    run_arp_scan,
    run_nmap_sweep,
)
from shield.agent.collectors.traffic import TrafficManager
from shield.agent.detectors.dns import BASELINE_DNS_SERVERS, DnsDetector
from shield.agent.detectors.endpoint import EndpointDetector
from shield.agent.detectors.local_log import LocalLogDetector
from shield.agent.detectors.mitm import BASELINE_GW_IP, BASELINE_GW_MAC, MitmDetector
from shield.agent.detectors.portscan import PortscanDetector
from shield.agent.detectors.unknown_device import UnknownDeviceDetector
from shield.agent.ipc import IpcServer
from shield.agent.livestats import LiveStats, idle_sources
from shield.ai.audit import InvestigationAudit
from shield.response.jobs import ResponseJobStore, TransitionError
from shield.agent.log_export import ExportConfig, LogExporter
from shield.agent.problems import ProblemReporter, detect_problems, problem_to_alert, resolved_message
from shield.agent.store import Store
from shield.agent import switch
from shield.agent.switch import ALL, MAX_PAUSE_S, MonitoringSwitch, set_switch
from shield.assessment.exporters import coverage
from shield.assessment.models import AssessmentProfile
from shield.assessment.runner import AssessmentRunner
from shield.common import sdnotify
from shield.common.models import Alert, Event, now
from shield.security import PolicyEngine, RiskScorer
from shield.security.policy import PolicyConfig
from shield.security.scoring import RiskContext
from shield.security import trust
from shield.security.correlation import CorrelationEngine, CorrelationRule
from shield.security.rules import RuleDetector
from shield.security.response import DeadManSwitch, Quarantine, ResponseExecutor, default_quarantine_root
from shield.security.analysis import LocalSummaryAnalyzer
from shield.security.anomaly import BEHAVIOR_KEY_FORMATS, LocalBaselineDetector
from shield.security.fleet import FleetControlServer, FleetRegistry, fleet_server_context
from shield.security.investigations import InvestigationService
from shield.security.mitre import (
    BehaviorChainDetector, Suppression, SuppressionPolicy, attack_coverage, enrich_alert,
)
from shield.security.tamper import ClockMonitor, signed_snapshot, verify_snapshot
from shield.security.telemetry import KernelTelemetrySelector
from shield.security.health import (
    CollectorSupervisor, RetentionPolicy, RuntimeMonitor, prune_managed_files,
    overall_health,
)
from shield.security.supply_chain import verify_update_manifest
from shield.assessment.lab import lab_manifest
from shield.privileged.client import PrivilegedClient

logger = logging.getLogger("shield.agent")

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

FAKE_RULES = [
    ("DEVICE_NEW", "info", "Thiết bị mới xuất hiện"),
    ("MITM_ARP_CONFLICT", "critical", "Một IP bị 2 MAC khác nhau claim"),
    ("MITM_GATEWAY_MAC_CHANGED", "critical", "MAC gateway đã đổi"),
    ("SCAN_PORTSCAN", "warning", "Có port scan nhắm vào máy bạn"),
    ("LOCAL_SSH_BRUTEFORCE", "warning", "SSH bị dò mật khẩu"),
]


class _ShutdownRequested(Exception):
    """Người dùng bấm "Tắt Shield" trong app — thoát sạch với mã 0.

    Quan trọng: mã thoát 0 + `Restart=on-failure` trong unit file nghĩa là
    systemd KHÔNG bật lại. Nếu để mã khác 0, agent sẽ tự sống lại sau vài
    giây và người dùng tưởng nút Tắt bị hỏng.
    """


SHUTDOWN = asyncio.Event()


def load_policy_engine() -> PolicyEngine:
    """Nạp cấu hình phản ứng. Mọi đường hỏng đều rơi về audit-only.

    Đây là chỗ dễ nhất để vô tình biến "an toàn theo mặc định" thành "an toàn
    trừ khi có file lạ": nếu đọc file hỏng mà vẫn chạy tiếp với cấu hình một
    nửa, kẻ tấn công chỉ cần làm hỏng file là đổi được hành vi.
    """
    path = os.environ.get("SHIELD_POLICY_CONFIG")
    if not path:
        return PolicyEngine(audit_only=True)
    key = os.environ.get("SHIELD_POLICY_PUBLIC_KEY")
    signature = os.environ.get("SHIELD_POLICY_SIGNATURE")
    try:
        config = PolicyConfig.load(
            Path(path),
            Path(key) if key else None,
            Path(signature) if signature else None,
        )
    except (OSError, ValueError) as exc:
        logger.error("Không nạp được policy config (%s) — giữ audit-only: %s", path, exc)
        return PolicyEngine(audit_only=True)
    logger.warning("Policy config đã nạp: mode=%s, ngưỡng=%d, %d rule, %d action tự động",
                   config.policy_mode, config.min_risk_score,
                   len(config.auto_rules), len(config.auto_actions))
    return PolicyEngine(config=config)


async def shutdown_watch_loop() -> None:
    await SHUTDOWN.wait()
    raise _ShutdownRequested


async def isolation_deadman_loop(
    dead_man: DeadManSwitch, store: Store, alert_bus: Bus,
    privileged_client: PrivilegedClient | None,
) -> None:
    """Gỡ cách ly đã quá hạn mà không được gia hạn.

    Vòng lặp này là thứ biến "cách ly" từ một nút nguy hiểm thành một nút
    dùng được: dù agent có chết giữa chừng, lần khởi động sau nó vẫn đọc lại
    hạn chót từ đĩa và gỡ.
    """
    await reconcile_isolation_on_start(dead_man, store, privileged_client)
    while True:
        await asyncio.sleep(15)
        for target in dead_man.expired():
            # KHÔNG phải unblock_ip. Bản trước gọi unblock_ip lên chính địa chỉ
            # QUẢN TRỊ — một địa chỉ chưa bao giờ bị chặn. Lệnh đó luôn "chạy
            # xong", luôn ghi audit "đã gỡ", và không gỡ gì cả: table cách ly
            # vẫn nguyên, máy vẫn nằm ngoài mạng. Gỡ cách ly là xoá table cách
            # ly, không phải xoá một phần tử khỏi set chặn IP.
            ok, message = await run_privileged_action(privileged_client, "release_isolation", {})
            if ok:
                dead_man.disarm(target)
            else:
                # Còn armed thì 15 giây nữa thử lại. Disarm khi gỡ hỏng nghĩa
                # là không ai thử nữa và máy nằm ngoài mạng vĩnh viễn.
                logger.error("Gỡ cách ly %s thất bại, sẽ thử lại: %s", target, message)
            store.add_audit_log("isolation_auto_rollback", {"target": target, "ok": ok}, message)
            logger.warning("Tự gỡ cách ly %s (hết hạn, không được gia hạn): %s", target, message)
            await alert_bus.publish(Alert(
                now(), "ISOLATION_AUTO_ROLLED_BACK", "warning" if ok else "critical",
                "Endpoint isolation expired and was rolled back automatically" if ok
                else "Endpoint isolation expired but rollback FAILED",
                f"Isolation of {target} was not renewed in time and has been lifted" if ok
                else f"Isolation of {target} expired but the firewall rules could not be removed",
                target, evidence={"observed": True, "target": target, "rollback_ok": ok,
                                  "message": message, "notify_always": not ok},
                playbook=["snapshot_state"],
            ))


async def reconcile_isolation_on_start(
    dead_man: DeadManSwitch, store: Store, privileged_client: PrivilegedClient | None,
) -> None:
    """Đối chiếu trạng thái đĩa với trạng thái kernel khi agent khởi động.

    Cửa sổ hỏng có thật: agent áp xong luật cách ly rồi chết TRƯỚC khi kịp ghi
    hạn chót ra đĩa. Lần khởi động sau, dead-man không nợ ai cả — không vòng
    lặp nào gỡ table đó, và máy nằm ngoài mạng cho tới khi có người tới tận nơi.

    Nguồn sự thật là kernel, không phải file trạng thái của chính agent.
    """
    if privileged_client is None:
        return
    if dead_man.armed():
        return  # Có người đang nợ; vòng lặp bình thường lo phần còn lại.
    try:
        from shield.agent import actions
        present, _ = await actions.isolation_state()
    except (OSError, RuntimeError) as exc:
        logger.warning("Không kiểm tra được trạng thái cách ly lúc khởi động: %s", exc)
        return
    if not present:
        return
    logger.error("Phát hiện cách ly mồ côi: table còn trong kernel nhưng không có "
                 "hạn chót nào trên đĩa. Agent đã chết giữa lúc áp luật. Gỡ ngay.")
    ok, message = await run_privileged_action(privileged_client, "release_isolation", {})
    store.add_audit_log("isolation_orphan_release", {"ok": ok}, message)


async def watchdog_loop(store: Store) -> None:
    """Ping systemd để `WatchdogSec=` phát hiện agent TREO.

    Chỉ ping khi vòng lặp sự kiện còn thật sự quay và store còn trả lời được
    — ping vô điều kiện thì watchdog chỉ chứng minh "tiến trình còn tồn tại",
    đúng thứ mà `Restart=` đã bắt được rồi, và bỏ sót đúng trường hợp cần
    bắt: agent còn sống nhưng đã kẹt.
    """
    interval = sdnotify.watchdog_interval_s()
    if interval <= 0:
        return
    sdnotify.notify("READY=1")
    logger.info("Watchdog systemd: ping mỗi %.0f giây", interval)

    async def alive() -> bool:
        """Store có trả lời không. Đây là thứ làm cái ping CÓ NGHĨA."""
        try:
            await asyncio.to_thread(store.get_baseline, "config_schema_version")
            return True
        except Exception:  # noqa: BLE001 — store hỏng thì ĐỪNG ping, để systemd restart
            logger.exception("Watchdog: store không trả lời — bỏ qua lần ping này")
            return False

    # Ping NGAY, trước khi ngủ lần đầu.
    #
    # `Type=simple`, nên systemd bắt đầu đếm `WatchdogSec` từ lúc KHỞI ĐỘNG
    # dịch vụ, không phải từ `READY=1`. Vòng cũ ngủ trọn một chu kỳ trước cái
    # ping đầu tiên, nên hạn thực tế là:
    #
    #     thời gian khởi động  +  interval  <  WatchdogSec
    #
    # Khởi động nguội đo được trên máy thật là ~46 giây (xác minh 4.990 bản ghi
    # forensic ledger, mở database, dựng collector, tất cả với page cache lạnh),
    # cộng 45 giây chu kỳ là 91 giây — quá hạn 90 giây ĐÚNG MỘT GIÂY. Khởi động
    # ấm chỉ mất 1,7 giây nên không bao giờ chạm, và đó là lý do lỗi này chỉ xuất
    # hiện lúc boot và trông như ngẫu nhiên.
    #
    # Ping đầu vẫn phải CHỨNG MINH được: nó chỉ được gửi sau khi store trả lời,
    # y hệt mọi ping sau. Đây không phải nới hạn, và cũng không phải một luồng
    # ping giả — nó chỉ thôi lãng phí trọn một chu kỳ trước lần chứng minh đầu.
    if await alive():
        sdnotify.notify("WATCHDOG=1")

    while True:
        await asyncio.sleep(interval)
        if await alive():
            sdnotify.notify("WATCHDOG=1")


async def broadcast_monitoring_state(ipc: IpcServer, monitoring: MonitoringSwitch) -> None:
    await ipc.broadcast("monitoring_state", monitoring.state().to_dict())


async def run_alert_consumer(alert_bus: Bus, store: Store, ipc: IpcServer,
                             exporter_box: dict | None = None) -> None:
    """Alert bus -> ghi SQLite (dedupe) -> broadcast xuống UI qua IPC -> notifier.

    Notifier chạy fire-and-forget (create_task): Telegram có thể mất tới 10s
    (timeout mạng), không được chặn alert tiếp theo xử lý trong lúc đó.
    """
    q = alert_bus.subscribe()
    scorer = RiskScorer()
    # Mặc định an toàn: ghi nhận quyết định, không bao giờ tự kiềm chế.
    # Cấu hình chỉ được nạp từ file ĐÃ KÝ; thiếu chữ ký thì rơi về audit-only
    # chứ không rơi về "tin file". Xem shield/security/policy.py.
    policy = load_policy_engine()
    # Correlation rule nạp từ file (mục B5) — thêm một chuỗi tấn công mới
    # không phải sửa mã nguồn nữa.
    correlation_path = Path(__file__).parent.parent / "rules" / "correlation.json"
    # Cùng khoá với event pack: bật ký thì ký TẤT CẢ, để trống một loại pack là
    # để trống cả cơ chế.
    correlation_key = (
        Path(os.environ["SHIELD_RULE_PUBLIC_KEY"])
        if os.environ.get("SHIELD_RULE_PUBLIC_KEY") else None
    )
    correlations = CorrelationEngine(
        CorrelationRule.load_all(correlation_path, correlation_key)
    )
    while True:
        alert: Alert = await q.get()
        alert = enrich_alert(alert)
        # Ngữ cảnh (giá trị tài sản / lặp lại / threat intel) đọc từ DB — xem
        # store.risk_context và security/scoring.py. Đọc trong thread riêng để
        # 4 truy vấn SQLite không chặn event loop khi alert dồn dập.
        context = RiskContext.from_dict(
            await asyncio.to_thread(store.risk_context, alert.subject)
        )
        assessment = scorer.assess(alert, context)
        decision = policy.decide(alert.rule_id, assessment.score)
        # Phase 0 (mục 0.3): policy sinh ĐỀ XUẤT, chưa thực thi. Proposal có ID
        # riêng, TTL, evidence và luôn requires_human=True — không có đường nào
        # từ nó tới privileged helper trước khi Phase 4 có apply/verify/rollback.
        proposal = policy.propose(
            alert.rule_id, assessment.score, "snapshot_state", alert.subject,
            evidence_refs=(f"alert:{alert.rule_id}:{alert.subject}",),
        )
        evidence = dict(alert.evidence)
        if proposal is not None:
            evidence["response_proposal"] = proposal.to_dict()
        evidence.setdefault("risk_reasons", list(assessment.reasons))
        evidence.setdefault("risk_factors", assessment.factors)
        suppression = SuppressionPolicy([
            Suppression(item["rule_pattern"], item["subject_pattern"], item["expires_ts"], item["reason"])
            for item in store.active_suppressions()
        ]).reason(alert)
        alert = replace(
            alert,
            evidence=evidence,
            risk_score=assessment.score,
            evidence_strength=assessment.evidence_strength,
            policy_action="suppressed" if suppression else decision.action,
        )
        is_assessment = bool(alert.evidence.get("assessment_id"))
        # Assessment vẫn ép 0: event tổng hợp phải hiện đủ, không gộp.
        store.insert_alert(
            alert, dedupe_window_s=0 if is_assessment else (alert.dedupe_window_s or 300))
        if trust.may_enter_forensic_ledger(alert):
            store.add_forensic_record("alert", alert.to_dict())
        store.add_audit_log(
            "policy_decision",
            {"rule_id": alert.rule_id, "subject": alert.subject, "risk_score": alert.risk_score},
            f"suppressed: {suppression}" if suppression else f"{decision.action}: {decision.reason}",
        )
        if proposal is not None and not suppression:
            store.add_audit_log("response_proposal", proposal.to_dict(),
                                "PROPOSED (chờ người duyệt; Phase 0 không tự thực thi)")
        if not is_assessment and not suppression:
            await ipc.broadcast("alert", alert.to_dict())
        logger.info("Alert: [%s] %s (%s)", alert.severity, alert.title, alert.subject)
        if exporter_box is not None:
            exporter = exporter_box["exporter"]
            if exporter.config.include_alerts and exporter.directory is not None:
                await asyncio.to_thread(exporter.write,
                                        {"record": "alert", **alert.to_dict()})
        # `notify_always`: vấn đề của chính Shield (problems.py) được gửi ra
        # ngoài kể cả ở mức warning — collector im lặng không phải "critical"
        # nhưng vẫn là thứ người dùng cần biết ngay. Vấn đề đã được chặn trùng
        # tại ProblemReporter nên không có nguy cơ dội thông báo.
        force_notify = bool(alert.evidence.get("notify_always"))
        if (alert.severity == "critical" or force_notify) and not is_assessment and not suppression:
            asyncio.create_task(notifier.notify(alert, force=force_notify))
        if not is_assessment and not suppression:
            # Correlation -> Incident (mục B5). Alert rời rạc là thứ người
            # điều tra phải tự ghép lại; incident là sự việc đã ghép sẵn, có
            # id, mức rủi ro, kỹ thuật MITRE và hành động khuyến nghị.
            #
            # Đặt SAU bộ lọc suppression là có chủ ý: alert đã bị người dùng
            # tắt tiếng không được âm thầm quay lại dưới dạng incident.
            for correlation in correlations.correlate(alert):
                incident = store.open_or_update_incident(
                    correlation_id=correlation.rule.id, subject=alert.subject,
                    title=correlation.rule.title, severity=correlation.rule.severity,
                    risk_score=assessment.score,
                    evidence_strength=assessment.evidence_strength,
                    mitre_techniques=list(correlation.rule.mitre_techniques),
                    recommended_action=correlation.rule.recommended_action,
                    contributing=correlation.contributing,
                    reason=correlation.reason,
                    # Bằng chứng: `events.event_id` của các alert đóng góp, đã
                    # lọc qua bảng `events`. Không suy đoán id nào — alert nào
                    # không mang được event_id thì không đóng góp tham chiếu.
                    evidence_refs=store.existing_event_ids(
                        item.get("event_id", "") for item in correlation.contributing),
                    # Tài sản: tra thẳng `graph_entities.canonical_key`. Nếu
                    # đồ thị chưa biết subject này thì danh sách rỗng — không
                    # bịa ra một thực thể để incident trông đầy đủ hơn.
                    asset_refs=store.entity_ids_for_key(alert.subject),
                )
                logger.warning("Incident %s: %s (%s)", incident["incident_id"][:8],
                               correlation.rule.title, alert.subject)
                await alert_bus.publish(correlation.alert)
                await ipc.broadcast("incidents_updated",
                                    {"incidents": store.list_incidents(limit=100)})


class LiveEvidenceFeed:
    """Vòi quan sát có trần cho giao diện. KHÔNG BAO GIỜ chặn đường event.

    Vì sao không broadcast thẳng: `IpcServer.broadcast` gọi `await w.drain()`.
    Nếu giao diện đọc chậm — cửa sổ bị thu nhỏ, máy bận, người dùng kéo bảng —
    thì `drain()` chờ, và nó chờ NGAY TRÊN vòng lặp mà mọi collector đang đẩy
    event vào. Một người xem làm nghẽn việc thu thập là điều không được phép
    xảy ra, dù chỉ một nhịp.

    Nên: đẩy vào một hàng đợi có trần bằng `put_nowait`. Đầy thì BỎ và ĐẾM.
    Người xem mất một dòng; detector không mất gì, vì event đã được ghi vào
    database trước đó rồi.

    `dropped` ở đây là giới hạn của MÀN HÌNH, không phải mất telemetry — hai
    con số đó được báo riêng, cùng lý do đã ghi ở `LogTab`.
    """

    def __init__(self, maxsize: int = 256) -> None:
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max(1, maxsize))
        self.dropped = 0
        self.sent = 0

    def offer(self, event) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1


async def live_evidence_loop(feed: LiveEvidenceFeed, ipc: IpcServer) -> None:
    """Đẩy event ra giao diện. Chậm ở đây chỉ làm ĐẦY hàng đợi, không làm chậm
    collector — đó là toàn bộ mục đích của việc tách vòng lặp này ra."""
    from shield.common.secrets import redact

    while True:
        event = await feed.queue.get()
        if not ipc.has_clients():
            # Không ai xem thì không mã hoá gì cả. Hàng đợi vẫn được rút để nó
            # không đầy và bắt đầu đếm "bỏ" một cách vô nghĩa.
            continue
        payload = event.to_dict()
        # Che bằng bộ luật CHUNG. "Raw" không có nghĩa là bỏ qua bảo vệ bí mật.
        payload["data"] = redact(payload.get("data", {}))
        await ipc.broadcast("evidence_event", payload)
        feed.sent += 1


async def run_event_consumer(
    event_bus: Bus, alert_bus: Bus, store: Store, detectors: list, ipc: IpcServer,
    live: LiveStats | None = None, exporter_box: dict | None = None,
    evidence_feed: "LiveEvidenceFeed | None" = None,
) -> None:
    """Collector -> Event bus -> ghi SQLite thô -> mỗi detector -> Alert bus (nếu có).

    Detector chạy đồng bộ (chỉ query SQLite/RAM, không I/O mạng) nên gọi trực
    tiếp, không cần to_thread — giữ đúng nguyên tắc collector không quyết định
    nguy hiểm, mọi detector đều nhận cùng Event, độc lập với nhau.

    Event từ journal cũng broadcast riêng cho UI (tab Log máy) — khác Alert,
    đây là luồng log thô đã lọc, không qua dedupe.
    """
    q = event_bus.subscribe()
    graph_failures = 0
    while True:
        ev: Event = await q.get()
        store.insert_event(ev)
        # Evidence graph (kế hoạch 2.0 mục 1.3). Chạy trong thread riêng: nó
        # ghi nhiều dòng cho mỗi event, và chặn event loop ở đây nghĩa là mọi
        # collector đứng chờ SQLite.
        #
        # Lỗi ở đây KHÔNG được làm mất event. Graph là lớp phân tích thêm; nếu
        # nó hỏng thì detection hiện có vẫn phải chạy nguyên vẹn — cùng nguyên
        # tắc với AI ở Phase 2, và nó áp dụng ngay từ bây giờ.
        try:
            await asyncio.to_thread(store.graph_ingest_event, ev)
            graph_failures = 0
        except (sqlite3.DatabaseError, ValueError) as exc:
            graph_failures += 1
            logger.warning("Không dựng được evidence graph cho %s/%s: %s",
                           ev.source, ev.kind, exc)
            # Một dòng log cảnh báo là thứ không ai đọc. Nếu graph hỏng liên
            # tục, tab Sức khoẻ phải nói ra — nếu không, người dùng sẽ mở tab
            # điều tra sau hai tuần và thấy một graph rỗng mà không hiểu vì sao.
            if graph_failures in (1, 10, 100) or graph_failures % 1000 == 0:
                store.set_collector_health(
                    "evidence_graph", "sqlite", False,
                    f"{graph_failures} lần dựng graph thất bại; gần nhất: {exc}",
                )
        if live is not None:
            # Đếm trong bộ nhớ ngay tại đây: đây là chỗ DUY NHẤT mọi event đi
            # qua, và đếm ở đây thì không phải hỏi lại database câu nào.
            live.record(ev)
        if exporter_box is not None:
            exporter = exporter_box["exporter"]
            if exporter.config.include_events and exporter.directory is not None:
                # Ghi đĩa trong thread riêng: thư mục người dùng chọn có thể
                # nằm trên ổ ngoài hay ổ mạng, và một lần ghi chậm ở đây sẽ
                # làm nghẽn TOÀN BỘ đường event của Shield.
                await asyncio.to_thread(exporter.write, ev.to_dict())
        if ev.source == "journal":
            await ipc.broadcast("log_event", ev.to_dict())
        if evidence_feed is not None:
            # `offer` là đồng bộ và không bao giờ chờ. Đây là điểm khác biệt
            # duy nhất và quan trọng nhất so với dòng `broadcast` phía trên.
            evidence_feed.offer(ev)
        for detector in detectors:
            for alert in detector.handle_event(ev):
                # Gắn nguồn gốc + hạ trần severity cho nguồn không xác thực.
                # Một chỗ duy nhất, xem security/trust.py.
                await alert_bus.publish(trust.stamp_alert(alert, ev))


# Nhịp bảo trì. Một lượt bị chặn trần (xem `SIZE_CAP_MAX_BATCHES`), nên khi còn
# backlog phải quay lại sớm — bằng không việc chặn trần chỉ biến một lần treo
# dài thành một đống rác không bao giờ dọn hết.
MAINTENANCE_INTERVAL_S = 6 * 3600
MAINTENANCE_BUSY_INTERVAL_S = 60


async def maintenance_loop(store: Store, alert_bus: Bus) -> None:
    """Retention, integrity, and daily backup without pruning forensic evidence."""
    policy = RetentionPolicy.from_env()
    while True:
        try:
            result = await asyncio.to_thread(
                store.maintain, policy.event_days, policy.alert_days, policy.snapshot_days,
                policy.database_max_bytes,
            )
            pcap_dir = Path(os.environ.get("SHIELD_PCAP_DIR", "/var/lib/shield/pcaps"))
            result["pcap"] = await asyncio.to_thread(
                prune_managed_files, pcap_dir, retention_days=policy.pcap_days,
                maximum_bytes=policy.pcap_max_bytes,
            )
            integrity_ok, integrity_message = await asyncio.to_thread(store.check_integrity)
            store.set_system_health(
                "database_integrity", 1 if integrity_ok else 0, "boolean",
                "healthy" if integrity_ok else "failed", integrity_message,
            )
            if not integrity_ok:
                await alert_bus.publish(Alert(
                    now(), "SHIELD_DATABASE_INTEGRITY_FAILED", "critical",
                    "Shield database integrity check failed", integrity_message,
                    str(store.path), evidence={"observed": True, "database": str(store.path),
                                               "integrity_result": integrity_message},
                    playbook=["snapshot_state"],
                ))
            automatic_backup = store.get_baseline("automatic_backup_enabled") != "0"
            last_backup = float(store.get_baseline("database_last_backup") or 0)
            if automatic_backup and time.time() - last_backup >= 86400:
                backup_path = store.path.parent / "backups" / f"shield-{int(time.time())}.db"
                await asyncio.to_thread(store.backup_database, backup_path)
                store.set_baseline("database_last_backup", str(time.time()))
                store.set_system_health("last_backup", time.time(), "unix_ts", "healthy", str(backup_path))
            checkpoint_path = Path(os.environ.get("SHIELD_FORENSIC_CHECKPOINT", str(store.path) + ".checkpoint.json"))
            await asyncio.to_thread(store.create_forensic_checkpoint, checkpoint_path)
            logger.info("Database maintenance: %s", result)
            store.set_system_health(
                "maintenance", 1, "boolean",
                "draining" if result.get("more_work") else "healthy",
                json.dumps(result, default=str)[:1000])
            backlog = bool(result.get("more_work"))
        except Exception as exc:
            # Tranh khoá WAL là chuyện BÌNH THƯỜNG khi giao diện đang đọc, và
            # nó phải là một lượt hỏng CÓ GIỚI HẠN chứ không phải một lần dừng
            # im lặng: đúng kiểu hỏng này đã tích backlog nhiều ngày trên máy
            # thật, cho tới khi một lần khởi động lại phải dọn tất cả cùng lúc
            # và bị systemd giết. Đánh dấu còn việc để lượt sau quay lại sớm.
            store.set_system_health("maintenance", 0, "boolean", "failed", str(exc)[:1000])
            logger.exception("Database maintenance failed")
            backlog = True
        # Còn việc thì quay lại sau MỘT PHÚT, không phải sáu tiếng.
        await asyncio.sleep(MAINTENANCE_BUSY_INTERVAL_S if backlog else MAINTENANCE_INTERVAL_S)


def _report_baseline_relearn(store: Store, detector) -> None:
    """Việc nén cảnh báo phải NHÌN THẤY ĐƯỢC.

    Một detector đang im lặng vì học lại trông y hệt một máy sạch. Nếu không
    có dòng này, người vận hành sẽ tưởng phát hiện hành vi đang chạy trong khi
    nó đang cố ý không nói gì.
    """
    active = store.relearning_kinds()
    suppressed = getattr(detector, "suppressed_by_relearn", {})
    if not active:
        if suppressed:
            store.set_collector_health(
                "behavior_baseline", "local-frequency", True,
                "học lại xong; phát hiện hành vi hoạt động bình thường trở lại")
            suppressed.clear()
        return
    now_ts = time.time()
    parts = []
    for kind, until in sorted(active.items()):
        hours = max(0.0, (until - now_ts) / 3600)
        parts.append(f"{kind}: còn {hours:.1f} giờ, đã nén {suppressed.get(kind, 0)}")
    store.set_collector_health(
        "behavior_baseline", "local-frequency", True,
        "đang học lại sau khi định dạng khoá đổi — " + "; ".join(parts),
        state="degraded")


async def runtime_health_loop(
    store: Store, event_bus: Bus, alert_bus: Bus, ipc: IpcServer,
    privileged_client: PrivilegedClient | None,
    baseline_detector=None, evidence_feed=None,
) -> None:
    monitor = RuntimeMonitor()
    pcap_dir = Path(os.environ.get("SHIELD_PCAP_DIR", "/var/lib/shield/pcaps"))
    while True:
        try:
            await asyncio.to_thread(monitor.sample, store, event_bus, alert_bus, pcap_dir)
            helper_ok = False
            helper_detail = "helper not configured"
            if privileged_client is not None:
                try:
                    response = await privileged_client.call("health", {})
                    helper_ok = bool(response.get("ok"))
                    helper_detail = str(response.get("message", ""))
                except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                    helper_detail = str(exc)
            store.set_collector_health(
                "privileged_helper", "unix-rpc", helper_ok, helper_detail,
                state="running" if helper_ok else "failed", last_heartbeat=time.time(),
                error_message="" if helper_ok else helper_detail,
            )
            if baseline_detector is not None:
                _report_baseline_relearn(store, baseline_detector)
            if evidence_feed is not None:
                # Số bỏ ở đây là giới hạn của NGƯỜI XEM, không phải mất
                # telemetry — nói rõ trong `detail` để không ai đọc nhầm.
                # `dropped_events=0` là CÓ CHỦ ĐÍCH, không phải bỏ sót. Việc
                # người xem đọc chậm là giới hạn màn hình, không phải mất
                # telemetry: mọi event vẫn nằm nguyên trong database và tra lại
                # được qua Expert Evidence. Cộng nó vào con số mất telemetry sẽ
                # biến một giao diện đang cuộn chậm thành một Shield đang mù.
                store.set_collector_health(
                    "evidence_feed", "bounded-queue", True,
                    f"{evidence_feed.sent} đã gửi tới giao diện, "
                    f"{evidence_feed.dropped} bỏ vì người xem đọc chậm "
                    f"(giới hạn màn hình, KHÔNG phải mất telemetry)",
                    dropped_events=0)
            await ipc.broadcast("runtime_health", {
                "collector_health": store.collector_health(),
                "system_health": store.system_health(),
            })
        except Exception:
            logger.exception("Runtime health sampling failed")
        await asyncio.sleep(30)


async def log_export_status_loop(ipc: IpcServer, exporter_box: dict,
                               live: LiveStats | None) -> None:
    """Cập nhật số liệu xuất log mỗi 30 giây.

    Không đẩy theo mỗi lần ghi: ở nhịp 20 event/giây thì đó là 20 lần đọc thư
    mục và 20 gói IPC mỗi giây, để cập nhật một con số người ta liếc mắt vài
    phút một lần.
    """
    while True:
        await asyncio.sleep(30)
        exporter = exporter_box["exporter"]
        if not exporter.config.enabled:
            continue
        try:
            status = await asyncio.to_thread(_log_export_status, exporter_box, live)
        except OSError as exc:
            logger.warning("Không đọc được trạng thái xuất log: %s", exc)
            continue
        await ipc.broadcast("log_export_status", status)


async def live_stats_loop(live: LiveStats, ipc: IpcServer, interval_s: float = 1.0) -> None:
    """Đẩy số liệu sống mỗi giây. Đây là thứ khiến bảng điều khiển sống.

    Gộp ở phía agent rồi mới gửi: một đợt quét cổng sinh hàng nghìn event mỗi
    giây, đẩy từng cái sẽ nghẽn IPC và đơ giao diện.
    """
    while True:
        await asyncio.sleep(interval_s)
        try:
            # Tạm dừng giám sát thì số phải đứng yên VÀ nói rõ là đang dừng —
            # số vẫn nhảy sau khi bấm dừng sẽ khiến người dùng không tin cái nút.
            paused = not switch.allows("passive")
            await ipc.broadcast("live_stats", live.snapshot(paused=paused))
        except Exception:
            logger.exception("live_stats_loop lỗi")


async def problem_watch_loop(
    store: Store, alert_bus: Bus, ipc: IpcServer, syslog_collector: SyslogCollector,
    live: LiveStats,
) -> None:
    """Theo dõi sức khoẻ của chính Shield và báo bằng tiếng Anh khi có vấn đề.

    Trước đây những thứ này chỉ nằm trong tab Sức khoẻ và journald: chỉ ai chủ
    động mở ra xem mới biết, đúng lúc đáng lẽ phải được báo.
    """
    reporter = ProblemReporter()
    previous_drops = 0
    while True:
        await asyncio.sleep(60)
        try:
            stats = syslog_collector.stats()
            problems = await asyncio.to_thread(
                detect_problems,
                store.collector_health(), store.list_probe_health(),
                stats, previous_drops, None, None,
                idle_sources(live.sources()),
                time.time() - live.started_ts,
            )
            drops = int(stats.get("kernel_dropped", 0) or 0)
            if drops >= 0:
                previous_drops = drops
            opened, resolved = reporter.sync(problems)
            for problem in opened:
                logger.warning("Vấn đề: %s", problem.title)
                await alert_bus.publish(problem_to_alert(problem))
            for problem in resolved:
                logger.info("Đã hết: %s", problem.title)
                await notifier.notify_text(resolved_message(problem))
            if opened or resolved:
                await ipc.broadcast("agent_problems", {
                    "problems": [
                        {"problem_id": p.problem_id, "severity": p.severity,
                         "title": p.title, "detail": p.detail, "remedy": p.remedy}
                        for p in reporter.active.values()
                    ],
                })
        except Exception:
            # Vòng lặp báo vấn đề mà tự chết vì một vấn đề thì mất luôn đường báo.
            logger.exception("problem_watch_loop lỗi")


async def tamper_monitor_loop(alert_bus: Bus, store: Store) -> None:
    """Detect runtime code changes and backward wall-clock jumps."""
    code_root = Path(__file__).resolve().parent.parent
    key = os.environ.get("SHIELD_INTEGRITY_HMAC_KEY", "").encode()
    baseline = await asyncio.to_thread(signed_snapshot, code_root, key)
    clock = ClockMonitor()
    store.set_collector_health("tamper_protection", "sha256+hmac", True, "runtime baseline active")
    while True:
        await asyncio.sleep(300)
        clock_result = clock.check()
        if not clock_result["ok"]:
            await alert_bus.publish(Alert(
                now(), "TAMPER_CLOCK_ROLLBACK", "critical", "System clock moved backwards",
                f"Observed rollback of {abs(clock_result['drift_s']):.1f}s", "system-clock",
                evidence=clock_result, playbook=["snapshot_state"],
            ))
        try:
            valid, changed = await asyncio.to_thread(verify_snapshot, baseline, code_root, key)
        except (OSError, ValueError) as exc:
            valid, changed = False, [str(exc)]
        if not valid:
            store.set_collector_health("tamper_protection", "sha256+hmac", False, "integrity mismatch")
            await alert_bus.publish(Alert(
                now(), "TAMPER_AGENT_FILES_CHANGED", "critical", "Shield installation changed at runtime",
                f"{len(changed)} protected paths changed", "shield-installation",
                evidence={"changed": changed[:100], "signed": bool(key)}, playbook=["snapshot_state"],
            ))


async def run_privileged_action(client: PrivilegedClient | None, action: str, params: dict) -> tuple[bool, str]:
    """Use helper when configured; dev mode without helper retains direct adapters."""
    if client is not None:
        try:
            response = await client.call(action, params)
            return bool(response.get("ok")), str(response.get("message", ""))
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            return False, f"privileged helper: {exc}"
    function = getattr(actions, action)
    value = next(iter(params.values()))
    return await function(value)


SCAN_SCHEDULE_KEY = "scan_schedule"
SCAN_SCHEDULE_LAST_RUN_KEY = "scan_schedule_last_run"
ROUTER_BACKEND_CONFIG_KEY = "router_backend_config"
ROUTER_TRAFFIC_POLL_INTERVAL_S = 30
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


async def run_quick_scan(store: Store, event_bus: Bus, ipc: IpcServer, interface: str | None) -> None:
    """arp-scan ngay lập tức, không chờ chu kỳ 60s — dùng cho nút "Quét nhanh"
    ở tab Thiết bị (công cụ chủ động, xem README mục UI/UX). Publish Event
    giống hệt `discovery_loop` để tái dùng UnknownDeviceDetector có sẵn."""
    if not switch.allows("active_scan"):
        await ipc.broadcast("scan_status", {"kind": "quick", "state": "paused", "ts": time.time()})
        logger.info("Quét nhanh bị bỏ qua: giám sát chủ động đang tạm dừng")
        return
    await ipc.broadcast("scan_status", {"kind": "quick", "state": "running", "ts": time.time()})
    try:
        hosts = await run_arp_scan(interface)
        for h in hosts:
            await event_bus.publish(Event(ts=now(), source="discovery", kind="host_seen", data=h))
        logger.info("Quét nhanh theo yêu cầu: thấy %d host", len(hosts))
    finally:
        await ipc.broadcast("scan_status", {"kind": "quick", "state": "done", "ts": time.time()})


async def run_deep_scan(store: Store, event_bus: Bus, ipc: IpcServer, interface: str | None) -> None:
    """nmap -sn toàn subnet ngay lập tức — nút "Quét sâu" hoặc lịch quét sâu
    tự động (Cài đặt). Có thể mất 1-2 phút, UI hiện `scan_status` để biết
    đang chạy, không phải app đứng hình."""
    if not switch.allows("active_scan"):
        await ipc.broadcast("scan_status", {"kind": "deep", "state": "paused", "ts": time.time()})
        logger.info("Quét sâu bị bỏ qua: giám sát chủ động đang tạm dừng")
        return
    await ipc.broadcast("scan_status", {"kind": "deep", "state": "running", "ts": time.time()})
    try:
        hosts = await run_nmap_sweep(interface)
        for h in hosts:
            await event_bus.publish(Event(ts=now(), source="discovery", kind="host_seen", data=h))
        logger.info("Quét sâu theo yêu cầu: thấy %d host", len(hosts))
    finally:
        await ipc.broadcast("scan_status", {"kind": "deep", "state": "done", "ts": time.time()})


async def run_self_audit(host: str, store: Store, ipc: IpcServer) -> None:
    """`self_port_scan` cho 1 host — chỉ máy mình (127.0.0.1) hoặc thiết bị đã
    tin cậy, không quét thiết bị lạ (đúng phạm vi "tự kiểm tra", không phải
    quét khai thác toàn mạng, xem KE-HOACH-SHIELD.md mục 7)."""
    if not switch.allows("active_scan"):
        logger.info("Tự kiểm tra cổng bị bỏ qua: giám sát chủ động đang tạm dừng")
        return
    allowed = host == "127.0.0.1" or any(
        d["ip"] == host and d["trusted"] for d in store.list_devices()
    )
    if not allowed:
        logger.warning("self_port_scan: host %r không phải máy mình hoặc thiết bị tin cậy, bỏ qua", host)
        return
    ok, msg, ports = await actions.self_port_scan(host)
    store.add_audit_log("self_port_scan", {"host": host}, msg if not ok else f"OK ({len(ports)} cổng)")

    diff = None
    if ok:
        # Lưu snapshot TRƯỚC khi diff — diff_latest_audit_snapshots() tự so
        # với lần lưu trước đó, nên phải ghi xong lần này rồi mới so được.
        store.save_audit_snapshot(host, ports)
        store.update_device_service_signals(host, ports)
        diff = store.diff_latest_audit_snapshots(host)
        if diff and (diff["added"] or diff["removed"]):
            logger.info(
                "self_port_scan %s: thay đổi so với lần quét trước — +%d/-%d cổng",
                host, len(diff["added"]), len(diff["removed"]),
            )

    await ipc.broadcast(
        "self_audit_result",
        {
            "host": host, "ok": ok, "error": None if ok else msg, "ports": ports,
            "ts": time.time(), "diff": diff,
        },
    )
    logger.info("self_port_scan %s: %s", host, "OK" if ok else f"THẤT BẠI ({msg})")


# --- Tự kiểm soát DNS ---

DNS_MONITOR_INTERVAL_S = 300


async def collect_dns_status(store: Store) -> dict:
    """Gom hiện trạng DNS của máy: resolver đang dùng, baseline đã lưu, và
    các dòng /etc/hosts bất thường. Chỉ đọc, không sửa gì."""
    servers, source = await dns_audit.read_resolvers()
    overrides = await asyncio.to_thread(dns_audit.read_hosts_overrides)
    baseline = store.get_baseline(BASELINE_DNS_SERVERS)
    return {
        "servers": servers,
        "source": source,
        "baseline": baseline.split(",") if baseline else [],
        "hosts_overrides": overrides,
        "ts": time.time(),
    }


async def dns_monitor_loop(store: Store, event_bus: Bus, ipc: IpcServer) -> None:
    """Định kỳ đọc resolver hiện tại và đẩy vào event bus — DnsDetector so
    với baseline và bắn DNS_RESOLVER_CHANGED nếu khác. Cũng broadcast hiện
    trạng để tab DNS trên UI tự cập nhật mà không cần bấm nút."""
    while True:
        try:
            status = await collect_dns_status(store)
            if status["servers"]:
                await event_bus.publish(
                    Event(
                        ts=now(),
                        source="dns_monitor",
                        kind="dns_resolvers",
                        data={"servers": status["servers"], "source": status["source"]},
                    )
                )
            # Đọc lại baseline SAU khi detector kịp xử lý event ở trên thì mới
            # đúng, nhưng event bus là async — chấp nhận lệch tối đa 1 chu kỳ,
            # UI vẫn có nút "Kiểm tra ngay" cho trường hợp cần chính xác ngay.
            await ipc.broadcast("dns_status", status)
        except Exception:
            logger.exception("Lỗi trong dns_monitor_loop")
        await asyncio.sleep(DNS_MONITOR_INTERVAL_S)


async def run_dns_hijack_check(ipc: IpcServer, store: Store) -> None:
    if not switch.allows("active_scan"):
        logger.info("Kiểm tra DNS hijack bị bỏ qua: giám sát chủ động đang tạm dừng")
        await ipc.broadcast("dns_hijack_result", {"ok": False, "paused": True,
                                                  "message": "Giám sát chủ động đang tạm dừng"})
        return
    ok, msg, results = await dns_audit.hijack_check()
    store.add_audit_log(
        "dns_hijack_check", {}, msg if not ok else f"OK ({len(results)} domain)"
    )
    await ipc.broadcast(
        "dns_hijack_result",
        {"ok": ok, "error": None if ok else msg, "results": results, "ts": time.time()},
    )
    logger.info("dns_hijack_check: %s", "OK" if ok else f"THẤT BẠI ({msg})")


# --- Né tránh khẩn cấp — đổi MAC + IP liên tục, CHỈ khi người dùng tự bật ---

EVASION_ENABLED_KEY = "evasion_enabled"
EVASION_INTERVAL_KEY = "evasion_interval_s"
# Cờ "đang để MAC bẩn" — set "1" NGAY TRƯỚC mỗi lần xoay MAC, chỉ xoá về "0"
# sau khi đã khôi phục MAC gốc sạch sẽ. Nếu agent bị kill cứng giữa lúc né
# tránh đang bật, baseline enabled vẫn "1" nên loop tự xoay tiếp (tự lành).
# Nhưng nếu người dùng đã TẮT rồi mà agent chết trước khi kịp restore, MAC sẽ
# kẹt ở giá trị ngẫu nhiên — cờ này để lần khởi động sau phát hiện và khôi
# phục lại MAC gốc 1 lần.
EVASION_DIRTY_KEY = "evasion_mac_dirty"
EVASION_DEFAULT_INTERVAL_S = 60
EVASION_MIN_INTERVAL_S = 20
EVASION_MAX_INTERVAL_S = 600
# Chu kỳ kiểm tra cờ bật/tắt — ngắn để TẮT có hiệu lực gần như ngay (khôi
# phục MAC gốc trong vài giây), không phải đợi hết 1 chu kỳ xoay dở dang.
EVASION_POLL_S = 3


def evasion_should_restore_on_boot(store: Store, iface: str | None) -> bool:
    """True nếu lúc khởi động cần khôi phục MAC gốc: có interface, cờ bẩn còn
    "1", nhưng né tránh hiện KHÔNG bật (tức lần trước tắt/chết mà chưa kịp
    restore). Tách riêng để test được không cần chạy nmcli."""
    return (
        bool(iface)
        and store.get_baseline(EVASION_DIRTY_KEY) == "1"
        and store.get_baseline(EVASION_ENABLED_KEY) != "1"
    )


def evasion_interval(store: Store) -> int:
    raw = store.get_baseline(EVASION_INTERVAL_KEY)
    try:
        val = int(raw) if raw else EVASION_DEFAULT_INTERVAL_S
    except ValueError:
        val = EVASION_DEFAULT_INTERVAL_S
    return min(EVASION_MAX_INTERVAL_S, max(EVASION_MIN_INTERVAL_S, val))


async def evasion_loop(store: Store, ipc: IpcServer, iface: str | None) -> None:
    """Luôn chạy nền, chi phí ~0 khi tắt (chỉ đọc 1 dòng baseline mỗi vài
    giây) — giống pattern scan_schedule_loop/dns_monitor_loop. Khi bật: xoay
    MAC/IP ngay lập tức rồi lặp lại theo chu kỳ đã cấu hình. Khi người dùng
    tắt: khôi phục MAC gốc ngay trong vòng lặp tiếp theo, không để máy kẹt
    lại ở 1 MAC ngẫu nhiên.
    """
    was_enabled = False
    next_rotation = 0.0

    # Phục hồi sau sự cố: agent chết cứng khi né tránh đang bật rồi người dùng
    # (hoặc lần chạy trước) đã tắt -> MAC còn kẹt ngẫu nhiên. Nếu hiện KHÔNG
    # bật mà cờ bẩn vẫn "1" thì khôi phục MAC gốc 1 lần lúc khởi động.
    if evasion_should_restore_on_boot(store, iface):
        logger.warning("evasion: phát hiện MAC còn bẩn từ lần chạy trước — khôi phục MAC gốc cho %s", iface)
        ok, msg = await evasion.restore_identity(iface)
        store.add_audit_log("evasion_restore_boot", {"iface": iface}, msg if not ok else "OK")
        if ok:
            store.set_baseline(EVASION_DIRTY_KEY, "0")

    while True:
        try:
            enabled = (bool(iface) and store.get_baseline(EVASION_ENABLED_KEY) == "1"
                       and switch.allows("active_scan"))
            now_ts = time.time()
            if enabled:
                if not was_enabled:
                    logger.warning(
                        "evasion: BẬT né tránh trên %s — MAC/IP sẽ đổi liên tục cho tới khi tắt",
                        iface,
                    )
                    next_rotation = 0.0  # xoay ngay lần đầu bật, không đợi hết chu kỳ
                if now_ts >= next_rotation:
                    # Đánh dấu bẩn TRƯỚC khi đổi — nếu chết ngay sau lệnh đổi,
                    # lần khởi động sau vẫn biết cần khôi phục.
                    store.set_baseline(EVASION_DIRTY_KEY, "1")
                    ok, msg, info = await evasion.rotate_identity(iface)
                    store.add_audit_log(
                        "evasion_rotate", {"iface": iface},
                        msg if not ok else f"OK mac={info.get('mac')} ip={info.get('ip')}",
                    )
                    await ipc.broadcast(
                        "evasion_status",
                        {
                            "enabled": True, "ok": ok, "error": None if ok else msg,
                            "mac": info.get("mac"), "ip": info.get("ip"), "ts": time.time(),
                            "interval_s": evasion_interval(store),
                        },
                    )
                    if not ok:
                        logger.error("evasion: xoay danh tính thất bại: %s", msg)
                    next_rotation = time.time() + evasion_interval(store)
                was_enabled = True
            elif was_enabled:
                ok, msg = await evasion.restore_identity(iface)
                store.add_audit_log("evasion_restore", {"iface": iface}, msg if not ok else "OK")
                if ok:
                    store.set_baseline(EVASION_DIRTY_KEY, "0")  # đã sạch, không cần khôi phục lúc boot
                await ipc.broadcast(
                    "evasion_status",
                    {"enabled": False, "ok": ok, "error": None if ok else msg, "ts": time.time()},
                )
                was_enabled = False
        except Exception:
            logger.exception("Lỗi trong evasion_loop")
        await asyncio.sleep(EVASION_POLL_S)


async def collect_evasion_status(store: Store, iface: str | None) -> dict:
    mac = await evasion.current_mac(iface) if iface else None
    ip = await evasion.current_ip(iface) if iface else None
    return {
        "enabled": store.get_baseline(EVASION_ENABLED_KEY) == "1",
        "interval_s": evasion_interval(store),
        "mac": mac,
        "ip": ip,
        "iface": iface,
        "ts": time.time(),
    }


# --- Tarpit phòng thủ — honeypot thụ động trên cổng mồi, CHỈ người dùng tự
# bật. Khác hẳn tính năng "gửi dữ liệu liên tục vào máy đối phương" đã bị từ
# chối (đó là tấn công chủ động): tarpit KHÔNG BAO GIỜ tự mở kết nối ra
# ngoài, chỉ giữ lại kết nối mà đối phương TỰ khởi tạo tới cổng mồi trên
# chính máy này (xem shield/agent/tarpit.py). ---

TARPIT_ENABLED_KEY = "tarpit_enabled"
TARPIT_PORTS_KEY = "tarpit_ports"
TARPIT_POLL_S = 5


def tarpit_configured_ports(store: Store) -> list[int]:
    raw = store.get_baseline(TARPIT_PORTS_KEY)
    ports = tarpit.parse_port_list(raw) if raw else []
    return ports or list(tarpit.DEFAULT_TARPIT_PORTS)


async def _on_tarpit_connection(store: Store, alert_bus: Bus, ipc: IpcServer, info: dict) -> None:
    store.add_audit_log(
        "tarpit_connection", {"ip": info["ip"], "port": info["port"]},
        f"Kết nối mồi từ {info['ip']} tới cổng {info['port']}",
    )
    await alert_bus.publish(
        Alert(
            ts=now(),
            rule_id="TARPIT_CONNECTION",
            severity="warning",
            title=f"Có kết nối vào cổng mồi {info['port']} từ {info['ip']}",
            detail=(
                f"{info['ip']} tự kết nối tới cổng mồi {info['port']} trên máy này — "
                "cổng này không chạy dịch vụ thật, chỉ để câu giờ. Shield đang giữ "
                "kết nối lại chậm rãi, không gửi gì ra ngoài phạm vi kết nối họ tự mở."
            ),
            subject=info["ip"],
            evidence={"ip": info["ip"], "port": info["port"]},
            playbook=["block_ip", "snapshot_state"],
        )
    )
    await ipc.broadcast("tarpit_connection", info)


async def tarpit_loop(
    store: Store, ipc: IpcServer, alert_bus: Bus, mgr: tarpit.TarpitManager
) -> None:
    """Luôn chạy nền, không mở cổng nào cho tới khi người dùng tự bật ở Cài
    đặt. Bật: mở server trên các cổng đã cấu hình (mặc định
    `tarpit.DEFAULT_TARPIT_PORTS` nếu chưa tuỳ chỉnh). Tắt: đóng hết server
    ngay, cắt mọi kết nối đang bị giữ.
    """
    mgr._on_new_connection = lambda info: asyncio.create_task(
        _on_tarpit_connection(store, alert_bus, ipc, info)
    )
    was_enabled = False
    while True:
        try:
            enabled = store.get_baseline(TARPIT_ENABLED_KEY) == "1" and switch.allows("capture")
            if enabled:
                ports = tarpit_configured_ports(store)
                opened, failed = await mgr.start(ports)
                if not was_enabled:
                    store.add_audit_log(
                        "set_tarpit", {"ports": ports},
                        f"BẬT — đang nghe {opened}" + (f", lỗi {failed}" if failed else ""),
                    )
                    logger.warning(
                        "tarpit: BẬT — đang nghe cổng %s%s",
                        opened, f" (lỗi mở: {failed})" if failed else "",
                    )
                was_enabled = True
                await ipc.broadcast(
                    "tarpit_status",
                    {
                        "enabled": True, "ports": mgr.active_ports, "failed_ports": failed,
                        "connections": mgr.list_connections(), "ts": time.time(),
                    },
                )
            elif was_enabled:
                await mgr.stop_all()
                store.add_audit_log("set_tarpit", {}, "TẮT")
                logger.warning("tarpit: TẮT — đã đóng hết cổng mồi")
                was_enabled = False
                await ipc.broadcast(
                    "tarpit_status",
                    {"enabled": False, "ports": [], "connections": [], "ts": time.time()},
                )
            elif mgr.active_ports:
                # Đang tắt nhưng vẫn có kết nối cũ bị giữ (VD agent restart
                # giữa chừng) -> vẫn cập nhật UI để không hiện sai trạng thái.
                await ipc.broadcast(
                    "tarpit_status",
                    {
                        "enabled": False, "ports": mgr.active_ports,
                        "connections": mgr.list_connections(), "ts": time.time(),
                    },
                )
        except Exception:
            logger.exception("Lỗi trong tarpit_loop")
        await asyncio.sleep(TARPIT_POLL_S)


_MAX_RANGE_AUDIT_HOSTS = 64


async def run_range_scan(cidr: str, store: Store, event_bus: Bus, ipc: IpcServer) -> None:
    """Quét một dải mạng đã được BẠN xác nhận cấp phép (bảng
    authorized_ranges) — dò host sống rồi hỏi banner dịch vụ từng host, cùng
    logic non-intrusive như self_port_scan (không NSE tấn công, không khai
    thác, đúng ranh giới mục 7 kế hoạch). `cidr` phải đã được handle_command
    đối chiếu với danh sách cấp phép trước khi gọi hàm này."""
    if not switch.allows("active_scan"):
        await ipc.broadcast("scan_status", {"kind": "range", "state": "paused", "ts": time.time(), "cidr": cidr})
        logger.info("Quét dải %s bị bỏ qua: giám sát chủ động đang tạm dừng", cidr)
        return
    await ipc.broadcast("scan_status", {"kind": "range", "state": "running", "ts": time.time(), "cidr": cidr})
    try:
        ok, msg, hosts = await actions.range_discovery_scan(cidr)
        store.add_audit_log(
            "scan_authorized_range", {"cidr": cidr}, msg if not ok else f"OK ({len(hosts)} host)"
        )
        if not ok:
            logger.error("scan_authorized_range %s thất bại: %s", cidr, msg)
            return

        for h in hosts:
            await event_bus.publish(Event(ts=now(), source="discovery", kind="host_seen", data=h))
        logger.info("scan_authorized_range %s: %d host sống", cidr, len(hosts))

        audit_hosts = hosts[:_MAX_RANGE_AUDIT_HOSTS]
        if len(hosts) > _MAX_RANGE_AUDIT_HOSTS:
            logger.warning(
                "scan_authorized_range %s: %d host sống, chỉ hỏi banner %d host đầu (giới hạn an toàn)",
                cidr, len(hosts), _MAX_RANGE_AUDIT_HOSTS,
            )
        for h in audit_hosts:
            ip = h.get("ip")
            if not ip:
                continue
            ok2, msg2, ports = await actions.self_port_scan(ip)
            store.add_audit_log(
                "range_port_scan", {"cidr": cidr, "host": ip},
                msg2 if not ok2 else f"OK ({len(ports)} cổng)",
            )
            await ipc.broadcast(
                "self_audit_result",
                {"host": ip, "ok": ok2, "error": None if ok2 else msg2, "ports": ports, "ts": time.time()},
            )
    finally:
        await ipc.broadcast("scan_status", {"kind": "range", "state": "done", "ts": time.time(), "cidr": cidr})


async def router_traffic_loop(store: Store, ipc: IpcServer, interface: str | None) -> None:
    """Poll router mỗi ROUTER_TRAFFIC_POLL_INTERVAL_S giây theo backend đã cấu
    hình (Cài đặt -> "Lưu lượng theo thiết bị", xem router_backends.py). Chi
    phí gần như 0 nếu chưa cấu hình (chỉ đọc 1 dòng baseline mỗi vòng),
    giống scan_schedule_loop — không cần cờ CLI riêng.

    Số byte router trả về là CỘNG DỒN — `_prev_cumulative` giữ lần poll
    trước (chỉ trong bộ nhớ, không cần bền vững) để tính delta/giây gửi UI;
    còn SQLite luôn lưu số cộng dồn mới nhất (list_router_traffic sắp theo
    tổng byte, không phải theo tốc độ)."""
    _prev_cumulative: dict[str, tuple[float, int, int]] = {}  # ip -> (ts, rx, tx)

    while True:
        try:
            if not switch.allows("active_scan"):
                await asyncio.sleep(ROUTER_TRAFFIC_POLL_INTERVAL_S)
                continue
            raw = store.get_baseline(ROUTER_BACKEND_CONFIG_KEY)
            config = json.loads(raw) if raw else {"type": "disabled"}
            if config.get("type") not in (None, "disabled"):
                lan_subnet = await asyncio.to_thread(
                    detect_subnet, interface or await asyncio.to_thread(detect_interface)
                )
                ok, msg, hosts = await router_backends.poll(config, lan_subnet)
                if not ok:
                    logger.warning("router_traffic_loop: %s", msg)
                    await ipc.broadcast("router_backend_error", {"error": msg})
                else:
                    now_ts = time.time()
                    result = []
                    for h in hosts:
                        ip = h["ip"]
                        store.upsert_router_traffic(ip, h.get("mac"), h["rx_bytes"], h["tx_bytes"])
                        prev = _prev_cumulative.get(ip)
                        rx_rate = tx_rate = 0.0
                        if prev:
                            dt = max(now_ts - prev[0], 1.0)
                            rx_rate = max(h["rx_bytes"] - prev[1], 0) / dt
                            tx_rate = max(h["tx_bytes"] - prev[2], 0) / dt
                        _prev_cumulative[ip] = (now_ts, h["rx_bytes"], h["tx_bytes"])
                        result.append({**h, "rx_rate": rx_rate, "tx_rate": tx_rate})
                    await ipc.broadcast("router_traffic_updated", {"hosts": result, "ts": now_ts})
        except Exception:
            logger.exception("Lỗi trong router_traffic_loop")
        await asyncio.sleep(ROUTER_TRAFFIC_POLL_INTERVAL_S)


async def scan_schedule_loop(store: Store, event_bus: Bus, ipc: IpcServer, interface: str | None) -> None:
    """Kiểm tra mỗi phút xem có tới giờ chạy lịch quét sâu chưa (Cài đặt ->
    "Lịch quét sâu"). Cấu hình đọc từ bảng `baseline` (tái dùng key/value đã
    có, không cần bảng riêng): {"enabled": bool, "days": [0..6], "time":
    "HH:MM"} với 0=Thứ 2 (Python weekday()). Chạy tối đa 1 lần/ngày (chống
    lặp lại trong cùng phút nếu loop đánh nhiều lần)."""
    while True:
        try:
            raw = store.get_baseline(SCAN_SCHEDULE_KEY)
            if raw:
                cfg = json.loads(raw)
                now_dt = datetime.now()
                today_str = now_dt.strftime("%Y-%m-%d")
                already_ran = store.get_baseline(SCAN_SCHEDULE_LAST_RUN_KEY) == today_str
                if (
                    cfg.get("enabled")
                    and not already_ran
                    and now_dt.weekday() in cfg.get("days", [])
                    and now_dt.strftime("%H:%M") == cfg.get("time")
                ):
                    logger.info("Lịch quét sâu tới giờ chạy (%s) — bắt đầu", cfg.get("time"))
                    store.set_baseline(SCAN_SCHEDULE_LAST_RUN_KEY, today_str)
                    await run_deep_scan(store, event_bus, ipc, interface)
                    await run_self_audit("127.0.0.1", store, ipc)
                    for dev in store.list_devices():
                        if dev["trusted"] and dev["ip"]:
                            await run_self_audit(dev["ip"], store, ipc)
        except Exception:
            logger.exception("Lỗi trong scan_schedule_loop")
        await asyncio.sleep(60)


async def run_default_assessment(
    store: Store, event_bus: Bus, ipc: IpcServer, client_id: str, request_id: str
) -> None:
    """Exercise the live event/detection/storage path with in-memory events.

    Assessment events are tagged, never sent to the response executor, and
    critical findings are excluded from desktop/Telegram notifications.
    """
    await ipc.send_to(client_id, "assessment_status", {
        "status": "running", "request_id": request_id,
    })
    try:
        profile_path = Path(__file__).resolve().parent.parent / "assessment" / "default-profile.json"
        profile = AssessmentProfile.load(profile_path)
        result = await AssessmentRunner([], event_bus=event_bus, store=store).run(profile)
        payload = result.to_dict()
        await ipc.send_to(client_id, "assessment_status", {
            "status": "done", "request_id": request_id,
            "result": payload, "coverage": coverage(payload),
        })
    except Exception as exc:
        logger.exception("Assessment failed")
        await ipc.send_to(client_id, "assessment_status", {
            "status": "error", "request_id": request_id, "error": str(exc),
        })


async def build_response_executor(store: Store, privileged_client, ipc,
                                  interface: str | None, dead_man=None):
    """Dựng executor với adapter và danh sách địa chỉ được bảo vệ.

    Gateway và DNS resolver đọc từ hệ thống MỖI LẦN, không cache: một danh sách
    bảo vệ lỗi thời nghĩa là Shield chặn đúng cái gateway mới của bạn.
    """
    from shield.agent import actions
    from shield.response.adapters.isolate_endpoint import IsolateEndpointAdapter
    from shield.response.adapters.rate_limit import RateLimitAdapter
    from shield.response.adapters.snapshot import SnapshotAdapter
    from shield.response.adapters.temporary_block import TemporaryBlockAdapter
    from shield.response.executor import ResponseExecutorV2
    from shield.response.jobs import ResponseJobStore

    async def read_nft() -> str:
        ok, out = await actions._run_capture(
            ["nft", "-j", "list", "table", "inet", "shield"])
        return out if ok else ""

    gateway = ""
    resolvers: tuple[str, ...] = ()
    try:
        from shield.agent.collectors.discovery import detect_gateway_ip

        gateway = detect_gateway_ip() or ""
    except Exception:  # noqa: BLE001 — thiếu gateway không được chặn cả tính năng
        gateway = ""
    try:
        found, _source = await dns_audit.read_resolvers()
        resolvers = tuple(found)
    except Exception:  # noqa: BLE001 — thiếu danh sách DNS không được chặn cả tính năng
        resolvers = ()

    def on_critical(job, detail: str) -> None:
        # Gỡ thất bại phải đi RA NGOÀI agent. Một sự cố về chính cơ chế phản
        # ứng mà chỉ được ghi vào database của cơ chế đó thì không ai đọc.
        store.add_audit_log("response_rollback_failed",
                            {"job_id": job.job_id, "action": job.action}, detail)
        asyncio.create_task(ipc.broadcast("alert", Alert(
            now(), "RESPONSE_ROLLBACK_FAILED", "critical",
            "Rollback failed and the system is in an unknown state",
            f"Action {job.action} could not be rolled back: {detail}",
            job.action,
            evidence={"job_id": job.job_id, "detail": detail, "notify_always": True},
            playbook=["snapshot_state"],
        ).to_dict()))

    async def read_isolation_nft() -> str:
        ok, out = await actions._run_capture(
            ["nft", "-j", "list", "table", "inet", "shield_isolation"])
        return out if ok else ""

    management = os.environ.get("SHIELD_MANAGEMENT_IP", "")
    adapters = {
        "snapshot_state": SnapshotAdapter(),
        "block_ip": TemporaryBlockAdapter(
            privileged_client, gateway=gateway, resolvers=resolvers,
            management=management, nft_reader=read_nft,
        ),
        "rate_limit_ip": RateLimitAdapter(
            privileged_client, gateway=gateway, resolvers=resolvers,
            management=management, nft_reader=read_nft,
        ),
        "isolate_endpoint": IsolateEndpointAdapter(
            privileged_client, dead_man=dead_man, nft_reader=read_isolation_nft,
        ),
    }
    return ResponseExecutorV2(ResponseJobStore(store.conn), adapters,
                              on_critical=on_critical)


def _run_response_job(executor, job_id: str) -> None:
    """Chạy job trong một event loop riêng, trong thread riêng.

    Một lượt áp + kiểm chứng có thể mất vài giây (gọi helper, đọc lại ruleset).
    Chạy nó trên event loop chính nghĩa là mọi collector đứng chờ.
    """
    asyncio.run(executor.run(job_id))


async def run_investigation(store: Store, incident_id: str) -> dict:
    """Một lượt điều tra read-only cho một incident.

    Provider lấy từ `SHIELD_AI_PROVIDER`, mặc định `disabled`. Tên lạ cũng ra
    `disabled` — cấu hình sai phải khiến Shield chạy KHÔNG có AI, chứ không
    phải khiến Shield không chạy.
    """
    from shield.ai.capability import ai_tools_killed
    from shield.ai.orchestrator import InvestigationOrchestrator
    from shield.ai.report import OutputValidator, render_report
    from shield.ai.prompts import build_request
    from shield.report.incident import build as build_incident_report
    from shield.report.scenarios import explanation_enabled
    from shield.ai.provider import select_provider
    from shield.evidence.queries import EvidenceQueries

    # THỨ TỰ CỔNG (Phase 3D limited rollout). Kịch bản chính danh quyết định
    # trước, model chỉ được mời vào sau — và chỉ khi CẢ HAI điều kiện đúng:
    # kịch bản đã chứng minh đủ, VÀ người vận hành đã bật provider bằng tay.
    #
    # Thiếu một trong hai -> `DisabledProvider`, tức là KHÔNG sinh worker nào.
    # Đây là chỗ "spawns = 0" được bảo đảm, không phải một lời hứa ở tầng trên.
    scenario_code, _source = _incident_scenario(store, incident_id)
    configured = os.environ.get("SHIELD_AI_PROVIDER", "disabled")
    # HAI cổng độc lập, và cả hai phải mở:
    #
    #   1. Quản trị viên cấu hình provider (biến môi trường trong unit file).
    #   2. Người vận hành BẬT TAY phần giải thích trong giao diện.
    #
    # Một cổng thôi là chưa đủ: cấu hình provider là việc cài đặt, còn bật giải
    # thích là việc chấp nhận rằng máy này sẽ chạy một model. Gộp chúng lại thì
    # cài đặt xong là model chạy, và không ai từng bấm đồng ý.
    opted_in = _explanation_opt_in(store)
    killed = ai_tools_killed()
    may_explain = (configured != "disabled"
                   and opted_in
                   and not killed
                   and explanation_enabled(scenario_code))
    # LÝ DO đóng cổng, không chỉ việc nó đóng. "Chỉ báo cáo tất định cho kịch
    # bản này" là câu ĐÚNG khi kịch bản chưa đủ chín, và là câu SAI khi người
    # vận hành vừa bấm kill switch trên một kịch bản đã bật — họ sẽ đi sửa
    # nhầm chỗ. Tắt tay và kill switch đều là "đang tắt"; chỉ cổng kịch bản
    # mới là "không đủ điều kiện".
    block = "" if may_explain else (
        "disabled" if (not opted_in or killed) else "ineligible")
    # Suy luận KHÔNG chạy ở đây. Nó mất ~15 giây trong khi báo cáo tất định mất
    # 0,1 giây, và lời gọi này nằm trong vòng đọc IPC — chờ model ở đây khoá
    # luôn mọi lệnh tiếp theo của client, để đổi lấy một thứ họ đã có ngay từ
    # đầu. `provider` luôn là `disabled` trên đường đồng bộ; văn xuôi đến sau
    # qua `SharedAiRunner`.
    provider = select_provider("disabled")
    queries = EvidenceQueries(store.conn, caller=f"investigation:{incident_id}")

    subjects = await asyncio.to_thread(store.incident_subjects, incident_id)
    entity_ids = await asyncio.to_thread(_entities_for_subjects, queries, subjects)
    request = await asyncio.to_thread(build_request, queries, incident_id, entity_ids)

    orchestrator = InvestigationOrchestrator(queries, provider)
    started = time.time()
    result, validation = await orchestrator.investigate(request)

    # Phase 3A: tầng cuối giữa "model nói vậy" và "người dùng đọc vậy".
    #
    # `EvidenceValidator` (đã chạy bên trong orchestrator) kiểm được các ref
    # bằng chứng. Nó KHÔNG kiểm được con số và định danh nằm trong CÂU VĂN —
    # một model có thể vượt mọi phép kiểm hiện có rồi vẫn viết "15 kết nối từ
    # 10.0.0.9" trong khi dữ liệu nói 12 và 10.0.0.8. Đây là chỗ chặn điều đó.
    original_summary = result.summary
    output = OutputValidator(orchestrator.validator)
    result, _evidence_report, metrics, dropped_prose = output.validate(result, request)
    report = render_report(result, request, metrics)

    # Lưu bền TRƯỚC khi phát đi. Khi lớp AI nói sai một điều quan trọng, câu
    # hỏi khó nhất không phải "nó nói gì" mà là "nó đã nhìn thấy gì lúc nó nói
    # câu đó?" — và lần khởi động lại thường xảy ra ngay sau sự cố.
    audit = InvestigationAudit(store.conn)
    try:
        await asyncio.to_thread(
            audit.record, result,
            validation={**validation, "policy_violations": orchestrator.policy_violations},
            tool_calls=orchestrator.tool_calls, started_ts=started,
            original_summary=original_summary, final_summary=result.summary,
            # Lý do dừng đi CÙNG chỉ số vào hồ sơ: một lượt dùng phương án
            # dự phòng không bao giờ được đọc lại như một lượt bình thường.
            output_metrics={**metrics.to_dict(),
                            "termination_reason": validation.get("termination_reason", ""),
                            "fallback_used": bool(validation.get("fallback_used"))},
            coordinator=validation.get("coordinator"))
        await asyncio.to_thread(
            audit.record_model_run, result.investigation_id,
            provider=result.provider, model=result.model, started_ts=started,
            elapsed_s=time.time() - started, ok=not result.errors,
            error="; ".join(result.errors)[:500])
    except (sqlite3.DatabaseError, ValueError) as exc:
        # Không lưu được hồ sơ KHÔNG được làm hỏng lượt điều tra: kết quả vẫn
        # tới được người dùng, chỉ là không tra lại được sau này.
        logger.error("Không lưu được hồ sơ điều tra %s: %s", incident_id, exc)

    # Phase 3C: sức khoẻ worker model vào bảng chung. `ai_model_worker` nằm
    # trong `NON_TELEMETRY_COMPONENTS`, nên nó KHÔNG trừ điểm sức khoẻ tổng —
    # một worker sập không làm Shield mù mảng nào.
    _publish_ai_health(store, provider, validation)

    payload = result.to_dict()
    payload["validation"] = validation
    payload["report"] = report
    # Phase 3D: báo cáo sự cố có KHUÔN, dựng từ dữ liệu chuẩn tắc của `store`.
    #
    # Nó nằm SAU `OutputValidator` có chủ ý: ba ô văn xuôi chỉ được lấy từ
    # `result` đã qua kiểm, nên một câu bịa số đã bị bỏ trước khi tới đây và ô
    # tương ứng rỗng theo. Kịch bản thì KHÔNG lấy từ `result` chút nào —
    # `correlation_id` của incident quyết định, nên báo cáo ra đầy đủ kể cả khi
    # AI tắt hẳn.
    try:
        report_payload = await asyncio.to_thread(
            build_incident_report, store, incident_id, result=result)
        enrichment_state = await asyncio.to_thread(
            _attach_enrichment, store, incident_id, report_payload,
            scenario_code, configured, may_explain, block)
        payload["incident_report"] = report_payload
        payload["ai_enrichment"] = enrichment_state
    except (sqlite3.DatabaseError, ValueError, KeyError) as exc:
        # Báo cáo hỏng KHÔNG được làm hỏng lượt điều tra.
        logger.error("Không dựng được báo cáo sự cố %s: %s", incident_id, exc)
    payload["output_metrics"] = metrics.to_dict()
    if dropped_prose:
        # Câu bị bỏ là sự kiện đáng ghi, không phải chi tiết im lặng: một model
        # liên tục bịa số là model cần bị tắt, và không ai thấy được điều đó
        # nếu việc bỏ câu diễn ra không tiếng động.
        logger.warning("Bỏ %d đoạn văn của model vì chứa giá trị không chuẩn tắc: %s",
                       len(dropped_prose), sorted(dropped_prose))
    payload["tool_calls"] = len(orchestrator.tool_calls)
    payload["policy_violations"] = orchestrator.policy_violations
    # Vì sao lượt này có (hoặc không có) văn xuôi model. Người đọc phải phân
    # biệt được "model im lặng" với "model chưa bao giờ được mời".
    payload["explanation"] = {
        "opted_in": opted_in,
        "scenario_code": scenario_code,
        "maturity": _explanation_maturity(scenario_code),
        "provider_configured": configured,
        "invoked": may_explain,
        "low_sample_confidence": _low_sample(scenario_code),
    }
    store.add_audit_log("investigation", {
        "incident_id": incident_id, "provider": result.provider,
        "hypotheses": len(result.hypotheses),
        "policy_violations": orchestrator.policy_violations,
    }, "OK" if not result.errors else "; ".join(result.errors))
    if orchestrator.policy_violations:
        # Model cố gọi tool ngoài chính sách là sự kiện an ninh, không phải một
        # dòng debug. Ở Phase 5 tỉ lệ này phải bằng 0 trong bộ gate bắt buộc.
        logger.error("Điều tra %s: %d lần gọi tool ngoài chính sách",
                     incident_id, orchestrator.policy_violations)
    return payload


EXPLANATION_OPT_IN_KEY = "ai_explanation_enabled"


def _explanation_opt_in(store) -> bool:
    """Người vận hành đã bật phần giải thích chưa. MẶC ĐỊNH LÀ CHƯA.

    `!= "1"` chứ không phải `!= "0"`: một tính năng chạy model cục bộ phải bật
    bằng một hành động, không phải tắt bằng một hành động. Cấu hình thiếu, cột
    thiếu, hay database mới đều ra "chưa bật" — và đó là câu trả lời đúng.
    """
    try:
        return store.get_baseline(EXPLANATION_OPT_IN_KEY) == "1"
    except Exception:  # noqa: BLE001 — cấu hình hỏng không được BẬT hộ ai
        return False


# Mã hỏng của worker -> mã hỏng của job. Một bảng DUY NHẤT, dùng cho cả lỗi
# ném ra lẫn lỗi trả về trong băng: hai bảng cho cùng một câu hỏi là hai bảng
# sẽ lệch nhau.
_WORKER_FAILURE_CODES = {
    "timeout": "timeout",
    "resource_limit": "resource_limit",
    "malformed_frame": "malformed_output",
    "oversized_response": "malformed_output",
    "kill_switch": "kill_switch",
    "scope_unavailable": "provider_unavailable",
    "spawn_failed": "provider_unavailable",
    "network_isolation_failed": "provider_unavailable",
    "runtime_unavailable": "provider_unavailable",
    "model_missing": "provider_unavailable",
}


def _job_failure_code(worker_code: str) -> str:
    return _WORKER_FAILURE_CODES.get(str(worker_code or ""), "internal_error")


async def execute_enrichment_job(store, job) -> tuple[dict | None, str]:
    """Chạy MỘT job làm giàu. -> (ô văn xuôi, mã hỏng).

    `(None, "")` nghĩa là bằng chứng đã đổi trong lúc suy luận: kết quả nói về
    một dữ liệu không còn tồn tại, nên nó bị đánh dấu `stale` và không gắn vào
    đâu cả.

    Mọi cổng được kiểm LẠI ở đây, không tin quyết định lúc xếp hàng: giữa lúc
    xếp và lúc chạy có thể đã qua vài phút, và kill switch tồn tại để bấm giữa
    chừng.
    """
    from shield.ai.capability import ai_tools_killed
    from shield.ai.enrichment import EnrichmentStore
    from shield.ai.model_config import from_environment
    from shield.ai.worker.protocol import WorkerRequest
    from shield.ai.worker.supervisor import WorkerFailure
    from shield.ai.local_model import LocalModelAnalyst
    from shield.report.incident import build as build_incident_report
    from shield.report.scenarios import explanation_enabled
    from shield.report.template import AiSlots, allowed_values, epistemic_state

    if ai_tools_killed():
        return None, "kill_switch"
    configured = os.environ.get("SHIELD_AI_PROVIDER", "disabled")
    if configured == "disabled":
        return None, "provider_unavailable"
    if not await asyncio.to_thread(_explanation_opt_in, store):
        # Người vận hành đã tắt giữa lúc job nằm trong hàng đợi.
        return None, "provider_unavailable"

    report = await asyncio.to_thread(build_incident_report, store, job.incident_id)
    scenario_code = report["incident_type"]["scenario_code"]
    if not explanation_enabled(scenario_code):
        return None, "provider_unavailable"

    # Khoá còn khớp không. Bằng chứng có thể đã đổi từ lúc xếp hàng.
    current, _version = await asyncio.to_thread(
        enrichment_key, store, job.incident_id, report,
        str(report.get("locale", job.locale)), configured)
    if current != job.fingerprint:
        return None, ""

    try:
        config = from_environment()
    except Exception:  # noqa: BLE001
        config = None
    if config is None:
        return None, "provider_unavailable"

    analyst = LocalModelAnalyst(config)
    context = {"scenario_code": scenario_code,
               "family": report["incident_type"]["family"],
               "severity": report["severity"]["level"],
               "confirmed_facts": report["confirmed_facts"],
               "validated_evidence": report["validated_evidence"]["refs"],
               "limitations": [item["key"] for item in report["limitations"]],
               # Shield chắc tới đâu. Worker dùng nó để chọn giọng; guard ở
               # đường ra vẫn kiểm lại độc lập.
               "epistemic_state": report.get("epistemic_state", "UNCONFIRMED")}
    request = WorkerRequest(request_id=job.job_id[:64], facts=(context,),
                            target_locale=job.locale, deadline_s=config.timeout_s)
    try:
        response = await analyst.supervisor.request(request)
    except WorkerFailure as exc:
        return None, _job_failure_code(exc.code)
    if not response.ok:
        # Mã của worker, KHÔNG phải một mã đoán bừa. Trước đây nhánh này trả
        # thẳng "malformed_output" cho mọi lỗi trong băng, nên một máy chưa cài
        # `llama-cpp-python` báo với người vận hành rằng model sinh ra rác —
        # và họ đi tìm lỗi chất lượng model thay vì đi cài runtime. Worker đã
        # nói đúng lý do; việc ở đây chỉ là đừng vứt nó đi.
        return None, _job_failure_code(response.failure_code)

    # Bằng chứng có thể đã đổi TRONG LÚC suy luận. Kiểm lại lần cuối.
    fresh = await asyncio.to_thread(build_incident_report, store, job.incident_id)
    again, _v = await asyncio.to_thread(
        enrichment_key, store, job.incident_id, fresh,
        str(fresh.get("locale", job.locale)), configured)
    if again != job.fingerprint:
        return None, ""

    raw = {name: str(response.result.get(name, "") or "")
           for name in ("analysis", "hypothesis_rationale", "why_this_matters")}
    # CÙNG bộ kiểm mà đường đồng bộ dùng: giọng, giá trị chuẩn tắc, che bí mật.
    # Không có phiên bản "nhẹ hơn" cho đường nền.
    alert = {"severity": report["severity"]["level"],
             "risk_score": report["severity"]["risk_score"],
             "subject": report["affected_asset"]["subject"],
             "evidence": report["confirmed_facts"]}
    state = epistemic_state(evidence_refs=report["validated_evidence"]["refs"])
    safe = AiSlots(**raw).cleaned(
        state=state, allowed=allowed_values(alert, report["validated_evidence"]["refs"]))
    if not any(safe.values()):
        return None, "validation_failed"
    return safe, ""


def enrichment_key(store, incident_id: str, report: dict, locale: str,
                   configured: str) -> tuple[str, str]:
    """-> (fingerprint, model_version) cho lượt giải thích này.

    Khoá gồm MỌI thứ ảnh hưởng tới đầu ra. Thiếu một thành phần nghĩa là có một
    cách để dữ liệu đổi mà khoá không đổi — và khi đó Shield phục vụ một đoạn
    giải thích đúng cho dữ liệu của hôm qua.
    """
    from shield.ai.enrichment import fingerprint, model_version
    from shield.ai.model_config import ModelConfig, from_environment

    try:
        config = from_environment() or ModelConfig()
    except Exception:  # noqa: BLE001 — cấu hình hỏng không được chặn báo cáo
        config = ModelConfig()
    version = model_version(config)
    # Chụp phần TẤT ĐỊNH của báo cáo: đó chính là thứ model được cho xem.
    evidence = {section: report.get(section) for section in
                ("incident_type", "severity", "confirmed_facts",
                 "validated_evidence", "epistemic_state")}
    return fingerprint(incident_id=incident_id, evidence=evidence, locale=locale,
                       provider=configured, model_version=version), version


def _attach_enrichment(store, incident_id: str, report: dict, scenario_code: str,
                       configured: str, may_explain: bool,
                       block: str = "ineligible") -> dict:
    """Gắn văn xuôi ĐÃ SẴN SÀNG nếu khoá khớp CHÍNH XÁC; nếu không thì xếp hàng.

    Không bao giờ tin một hàng `ready` mà không so lại khoá: một đoạn giải thích
    đúng cho dữ liệu cũ là một đoạn SAI cho dữ liệu mới, và nó không tự nói ra
    điều đó.
    """
    from shield.ai import enrichment as E
    from shield.ai.enrichment import EnrichmentStore
    from shield.ai.enrichment_runner import client_status
    from shield.report.scenarios import explanation_maturity

    locale = str(report.get("locale", "vi"))
    state = {"status": E.CLIENT_DISABLED, "scenario_code": scenario_code,
             "maturity": explanation_maturity(scenario_code),
             "provider_configured": configured, "failure_code": "", "job_id": ""}
    if configured == "disabled":
        return state
    if not may_explain:
        state["status"] = (E.CLIENT_DISABLED if block == "disabled"
                           else E.CLIENT_INELIGIBLE)
        return state

    try:
        jobs = EnrichmentStore(store.conn)
        key, version = enrichment_key(store, incident_id, report, locale, configured)
        state["fingerprint"] = key
        slots = jobs.ready_slots(key)
        if slots:
            _apply_slots(report, slots)
            state["status"] = E.CLIENT_READY
            return state
        job, reason = jobs.enqueue(
            incident_id=incident_id, fingerprint_value=key, locale=locale,
            provider=configured, model_version_value=version)
        if job is None:
            # Hàng đợi đầy. Báo cáo tất định vẫn ra bình thường — đây là một
            # trạng thái, không phải một lỗi.
            state["status"] = E.CLIENT_DEFERRED
            state["failure_code"] = reason
            return state
        state["status"] = client_status(job)
        state["job_id"] = job.job_id
        state["failure_code"] = job.failure_code
    except Exception as exc:  # noqa: BLE001 — làm giàu không được chặn báo cáo
        logger.warning("Không xếp hàng được job làm giàu %s: %s", incident_id, exc)
        state["status"] = E.CLIENT_DEFERRED
        state["failure_code"] = "internal_error"
    return state


def _apply_slots(report: dict, slots: dict) -> None:
    """Đưa ba ô ĐÃ KIỂM vào báo cáo. Chỉ ba ô, không gì khác."""
    report["analysis"] = {
        "prose": str(slots.get("analysis", "")),
        "hypothesis_rationale": str(slots.get("hypothesis_rationale", "")),
        "ai_generated": bool(slots.get("analysis") or slots.get("hypothesis_rationale")),
    }
    report["why_this_matters"] = {
        "prose": str(slots.get("why_this_matters", "")),
        "ai_generated": bool(slots.get("why_this_matters")),
    }


def _incident_scenario(store, incident_id: str) -> tuple[str, str]:
    """Kịch bản chính danh của incident. Đọc TRƯỚC khi quyết định mời model.

    Không bao giờ ném: không tra được thì `UNKNOWN`, và `UNKNOWN` luôn luôn là
    tất định-thuần — nên một lỗi ở đây fail closed đúng hướng.
    """
    from shield.report.incident import primary_scenario
    from shield.report.scenarios import UNKNOWN

    try:
        incident = store.incident(incident_id) or {}
        alerts = store.incident_alerts(incident_id) if incident else []
        return primary_scenario(incident, alerts)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Không tra được kịch bản của %s: %s", incident_id, exc)
        return UNKNOWN, "unknown"


def _explanation_maturity(scenario_code: str) -> str:
    from shield.report.scenarios import explanation_maturity

    return explanation_maturity(scenario_code)


def _low_sample(scenario_code: str) -> bool:
    """Mã này có ít mẫu tới mức người vận hành nên biết không.

    Giữ để QUAN SÁT, không để chặn: họ đã bật thì mã vẫn được giải thích, nhưng
    bằng chứng đằng sau nó còn mỏng và điều đó phải đọc được.
    """
    from shield.report.scenarios import LOW_SAMPLE_CONFIDENCE

    return str(scenario_code) in LOW_SAMPLE_CONFIDENCE


def _publish_ai_health(store, provider, validation: dict) -> None:
    """Trạng thái lớp AI sau một lượt điều tra. Không bao giờ ném.

    Không ghi được sức khoẻ KHÔNG được làm hỏng lượt điều tra: kết quả vẫn phải
    tới người dùng, y như với hồ sơ audit.
    """
    from shield.ai.capability import ai_tools_killed
    from shield.ai.worker.supervisor import WorkerHealth, publish_health

    try:
        supervisor = getattr(provider, "supervisor", None)
        if supervisor is None or ai_tools_killed():
            # Không có worker: provider `disabled`, kịch bản chưa đủ chín, hoặc
            # kill switch bật. Cả ba là "đang tắt đúng như mong đợi" — trạng
            # thái `disabled`, KHÔNG phải `degraded`.
            #
            # Phân biệt hai thứ này quan trọng: `degraded` nghĩa là có gì đó
            # hỏng và ai đó nên xem; `disabled` nghĩa là mọi thứ đúng như cấu
            # hình. Trộn chúng lại thì một dashboard vàng vĩnh viễn sẽ dạy
            # người dùng bỏ qua màu vàng.
            publish_health(store, WorkerHealth(), enabled=False)
            return
        health = supervisor.health
        if validation.get("fallback_used"):
            health.fallbacks += 1
        publish_health(store, health, enabled=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Không ghi được sức khoẻ lớp AI: %s", exc)


def _entities_for_subjects(queries, subjects) -> list[str]:
    """Tìm thực thể graph khớp với các đối tượng của incident.

    Đối tượng của incident là chuỗi tự do (IP, MAC, danh tính tiến trình), nên
    phải dò qua vài loại. Không tìm thấy thì trả rỗng — một cuộc điều tra không
    có điểm bắt đầu tốt hơn là một cuộc điều tra bắt đầu từ chỗ sai.
    """
    from shield.evidence.models import ENTITY_TYPES

    found: list[str] = []
    for subject in list(subjects)[:20]:
        text = str(subject or "").strip()
        if not text:
            continue
        for entity_type in ("process", "ip", "device", "user", "host", "file"):
            if entity_type not in ENTITY_TYPES:
                continue
            for key in (text, f"local:{text}"):
                node = queries.find_entity(entity_type, key)
                if node is not None:
                    found.append(node["entity_id"])
                    break
    return list(dict.fromkeys(found))[:20]


def _log_export_status(exporter_box: dict, live: LiveStats | None) -> dict:
    """Thông tin xuất log cho giao diện.

    Nhịp ghi lấy từ LiveStats — con số đang chạy trong bộ nhớ, không phải một
    câu truy vấn database. Nhờ nó, ước tính "hạn mức này giữ được bao nhiêu
    ngày" phản ánh đúng máy NÀY chứ không phải một con số trung bình bịa ra.
    """
    exporter = exporter_box["exporter"]
    rate = 0.0
    if live is not None:
        try:
            rate = float(live.rate())
        except (TypeError, ValueError):
            rate = 0.0
    from shield.agent.log_export import MAX_QUOTA_MB, MIN_QUOTA_MB, QUOTA_CHOICES_MB

    status = exporter.stats(rate_lines_per_s=rate)
    status["quota_choices_mb"] = list(QUOTA_CHOICES_MB)
    status["quota_min_mb"] = MIN_QUOTA_MB
    status["quota_max_mb"] = MAX_QUOTA_MB
    return status


async def handle_command(
    msg: dict,
    store: Store,
    interface: str | None,
    traffic_manager: TrafficManager,
    event_bus: Bus,
    ipc: IpcServer,
    tarpit_manager: tarpit.TarpitManager,
    response_executor: ResponseExecutor,
    privileged_client: PrivilegedClient | None,
    health_status: dict,
    monitoring: MonitoringSwitch,
    syslog_collector: SyslogCollector,
    ingest_server: LogIngestServer | None,
    exporter_box: dict,
    live: LiveStats | None = None,
) -> None:
    """Allowlist lệnh từ UI — agent validate lại mọi thứ, không tin UI.

    Giai đoạn 1: trust_device (ghi DB, không đụng hệ thống).
    Giai đoạn 2: set_gateway_baseline (ghi DB), pin_gateway_arp (đụng hệ
    thống thật, `ip neigh replace`) — "vũ khí chống MITM mạnh nhất".
    Giai đoạn 3: watch_device/unwatch_device (bật/tắt tcpdump + đếm traffic
    cho 1 IP — mục 2.5, không sniff toàn mạng liên tục).
    Giai đoạn 5: block_ip/unblock_ip, block_mac/unblock_mac (nftables, tự
    hết hạn 24h), snapshot_state (chụp ip neigh/ss/nft ruleset).
    Công cụ chủ động (UI/UX): discover_now/discover_deep (quét ngay theo
    yêu cầu), self_port_scan (tự kiểm tra máy mình/thiết bị tin cậy),
    set_scan_schedule (lịch quét sâu tự động).
    Quét ngoài mạng nhà: add_authorized_range/remove_authorized_range (quản
    lý danh sách CIDR đã cấp phép), scan_authorized_range (chỉ chạy nếu cidr
    yêu cầu nằm trong danh sách đó — xem run_range_scan).
    Lưu lượng theo thiết bị: set_router_backend (cấu hình ssh_conntrack/
    custom_script/disabled — xem router_backends.py), poll_router_traffic_now
    (quét ngay, không chờ chu kỳ 30s của router_traffic_loop),
    detect_gateway_ip_now (tự dò IP gateway hiện tại — điền sẵn ô "IP
    router" cho UI, đỡ phải gõ tay/tra thủ công).
    list_wifi_passwords: đọc lại SSID + mật khẩu WiFi NetworkManager của
    CHÍNH máy này đã lưu sẵn (không dò/bẻ mật khẩu mạng khác — mục 7).
    set_evasion/evasion_status_now: bật/tắt né tránh khẩn cấp (đổi MAC + IP
    liên tục qua NetworkManager, chỉ khi người dùng tự bật — xem evasion.py).
    set_tarpit/tarpit_status_now: bật/tắt honeypot thụ động trên cổng mồi —
    chỉ phản ứng lại kết nối đối phương TỰ khởi tạo, không bao giờ tự gửi gì
    ra ngoài (xem tarpit.py).
    """
    cmd = msg.get("cmd")
    peer = msg.get("_peer") if isinstance(msg.get("_peer"), dict) else {}
    client_id = str(peer.get("client_id", ""))
    principal = f"uid={peer.get('uid', '?')}:pid={peer.get('pid', '?')}:client={client_id}"
    request_id = str(msg.get("request_id", ""))

    if cmd == "health_status_now":
        configured_helper = os.environ.get("SHIELD_HELPER_SOCK")
        health_status["components"]["privileged_helper"] = bool(
            configured_helper and Path(configured_helper).exists()
        )
        await ipc.send_to(client_id, "health_status", {**health_status, "request_id": request_id, "ts": time.time()})

    elif cmd == "assessment_run_default":
        # Only the bundled, reviewed local-only profile is exposed over IPC.
        # Custom profiles stay in the explicit shield-assess CLI workflow.
        asyncio.create_task(
            run_default_assessment(store, event_bus, ipc, client_id, request_id)
        )

    elif cmd == "assessment_history_now":
        await ipc.send_to(client_id, "assessment_history", {
            "request_id": request_id, "sessions": store.recent_assessments(limit=20),
        })

    elif cmd == "set_backup_policy":
        if not isinstance(msg.get("enabled"), bool):
            await ipc.send_to(client_id, "command_error", {
                "request_id": request_id, "error": "enabled must be boolean",
            })
            return
        enabled = bool(msg["enabled"])
        store.set_baseline("automatic_backup_enabled", "1" if enabled else "0")
        store.add_audit_log("set_backup_policy", {"enabled": enabled, "principal": principal}, "OK")
        await ipc.send_to(client_id, "backup_status", {
            "request_id": request_id, "enabled": enabled,
            "last_backup": float(store.get_baseline("database_last_backup") or 0),
        })

    elif cmd == "backup_status_now":
        await ipc.send_to(client_id, "backup_status", {
            "request_id": request_id,
            "enabled": store.get_baseline("automatic_backup_enabled") != "0",
            "last_backup": float(store.get_baseline("database_last_backup") or 0),
        })

    elif cmd == "backup_now":
        try:
            backup_path = store.path.parent / "backups" / f"shield-manual-{int(time.time())}.db"
            await asyncio.to_thread(store.backup_database, backup_path)
            completed = time.time()
            store.set_baseline("database_last_backup", str(completed))
            store.set_system_health("last_backup", completed, "unix_ts", "healthy", str(backup_path))
            store.add_audit_log("backup_database", {"principal": principal}, f"OK: {backup_path}")
            await ipc.send_to(client_id, "backup_status", {
                "request_id": request_id,
                "enabled": store.get_baseline("automatic_backup_enabled") != "0",
                "last_backup": completed, "path": str(backup_path), "ok": True,
            })
        except (OSError, ValueError) as exc:
            store.add_audit_log("backup_database", {"principal": principal}, f"FAILED: {exc}")
            await ipc.send_to(client_id, "backup_status", {
                "request_id": request_id, "ok": False, "error": str(exc),
                "enabled": store.get_baseline("automatic_backup_enabled") != "0",
            })

    elif cmd == "advanced_status_now":
        alerts = store.recent_alerts(limit=2000)
        await ipc.send_to(client_id, "advanced_status", {
            "request_id": request_id,
            "collector_health": store.collector_health(),
            "system_health": store.system_health(),
            "database": store.database_stats(),
            "baseline": store.behavior_baseline_summary(),
            "cases": store.list_cases(),
            "endpoints": store.list_endpoints(),
            "mitre": attack_coverage(alerts),
            "lab": lab_manifest(),
            "suppressions": store.active_suppressions(),
            # Probe và syslog (kế hoạch 1.1 phần A) — gửi kèm luôn để UI khỏi
            # phải hỏi thêm một vòng nữa.
            "probes": store.list_probe_health(),
            "syslog": syslog_collector.stats(),
            "log_ingest_enabled": ingest_server is not None,
            "overall_health": overall_health(store.collector_health(), store.system_health()),
        })

    elif cmd == "security_search":
        query = str(msg.get("query", "")).strip()
        records = store.search_security_records(query, limit=500) if query else []
        await ipc.send_to(client_id, "security_search_result", {
            "request_id": request_id, "query": query, "records": records,
        })

    elif cmd == "case_create":
        title, subject = str(msg.get("title", "")).strip(), str(msg.get("subject", "")).strip()
        rules = msg.get("alert_rules", []) if isinstance(msg.get("alert_rules"), list) else []
        if title and subject:
            case = InvestigationService(store).create_case(title, subject, list(map(str, rules)))
            await ipc.send_to(client_id, "case_updated", {"request_id": request_id, "case": case, "cases": store.list_cases()})

    elif cmd == "case_state":
        try:
            InvestigationService(store).set_state(str(msg.get("case_id", "")), str(msg.get("state", "")))
            await ipc.send_to(client_id, "case_updated", {"request_id": request_id, "cases": store.list_cases()})
        except ValueError as exc:
            await ipc.send_to(client_id, "command_error", {"request_id": request_id, "error": str(exc)})

    elif cmd == "case_note":
        try:
            InvestigationService(store).add_note(str(msg.get("case_id", "")), principal, str(msg.get("note", "")))
            await ipc.send_to(client_id, "case_updated", {"request_id": request_id, "cases": store.list_cases()})
        except ValueError as exc:
            await ipc.send_to(client_id, "command_error", {"request_id": request_id, "error": str(exc)})

    elif cmd == "baseline_reset":
        if msg.get("confirm") is True:
            store.reset_behavior_baseline()
            await ipc.send_to(client_id, "advanced_status", {
                "request_id": request_id, "baseline": store.behavior_baseline_summary(),
                "collector_health": store.collector_health(), "system_health": store.system_health(),
                "database": store.database_stats(), "cases": store.list_cases(),
                "endpoints": store.list_endpoints(), "mitre": attack_coverage(store.recent_alerts(2000)),
                "lab": lab_manifest(), "suppressions": store.active_suppressions(),
            })

    elif cmd == "suppression_add":
        rule_pattern = str(msg.get("rule_pattern", "")).upper()
        subject_pattern = str(msg.get("subject_pattern", "*")).strip() or "*"
        try:
            hours = max(1.0, min(720.0, float(msg.get("hours", 24))))
        except (TypeError, ValueError):
            hours = 24.0
        if re.fullmatch(r"[A-Z0-9_*?.-]{1,100}", rule_pattern) and len(subject_pattern) <= 300:
            store.add_suppression(rule_pattern, subject_pattern, time.time() + hours * 3600, str(msg.get("reason", "analyst exception"))[:500])
            await ipc.send_to(client_id, "suppression_updated", {"request_id": request_id, "suppressions": store.active_suppressions()})

    elif cmd == "fleet_enroll":
        try:
            endpoint = FleetRegistry(store).enroll(
                str(msg.get("display_name", "")), str(msg.get("certificate_pem", "")).encode(),
                str(msg.get("role", "viewer")),
            )
            store.add_forensic_record("fleet_enrollment", {"endpoint_id": endpoint.endpoint_id, "fingerprint": endpoint.certificate_fingerprint, "role": endpoint.role})
            await ipc.send_to(client_id, "fleet_updated", {"request_id": request_id, "endpoints": store.list_endpoints()})
        except ValueError as exc:
            await ipc.send_to(client_id, "command_error", {"request_id": request_id, "error": str(exc)})

    elif cmd == "response_preview":
        action = str(msg.get("action", ""))
        params = msg.get("params", {}) if isinstance(msg.get("params"), dict) else {}
        token, result = await response_executor.preview(action, params, owner=principal)
        store.add_audit_log("response_preview", {"action": action, "params": params}, result.message)
        await ipc.send_to(client_id, "response_result", {**result.__dict__, "phase": "preview", "token": token, "request_id": request_id})

    elif cmd == "response_execute":
        action = str(msg.get("action", ""))
        params = msg.get("params", {}) if isinstance(msg.get("params"), dict) else {}
        token = str(msg.get("token", ""))
        result = await response_executor.execute(token, action, params, owner=principal)
        store.add_audit_log("response_execute", {"action": action, "params": params}, result.message)
        await ipc.send_to(client_id, "response_result", {**result.__dict__, "phase": "execute", "token": None, "request_id": request_id})

    elif cmd == "analyze_alerts":
        try:
            limit = min(2000, max(1, int(msg.get("limit", 500))))
        except (TypeError, ValueError):
            limit = 500
        lang = "vi" if msg.get("lang") == "vi" else "en"
        result = await LocalSummaryAnalyzer().analyze(store.recent_alerts(limit=limit), lang=lang)
        store.add_audit_log("local_analysis", {"limit": limit}, f"analyzed {result.record_count} records")
        await ipc.send_to(client_id, "analysis_result", {**result.__dict__, "request_id": request_id})

    elif cmd in {"response_jobs_now", "response_job_detail", "response_approve",
                 "response_deny", "response_rollback"}:
        # Hàng đợi phản ứng (kế hoạch 2.0 Phase 4). Mọi thao tác đi qua
        # ResponseExecutorV2 để máy trạng thái là nơi DUY NHẤT biết luật —
        # một đường tắt ở đây nghĩa là một job đổi trạng thái mà lịch sử không
        # ghi lại, và lịch sử là toàn bộ giá trị của lớp này.
        jobs_store = ResponseJobStore(store.conn)
        executor = await build_response_executor(
            store, privileged_client, ipc, interface, response_executor.dead_man)
        job_id = str(msg.get("job_id", ""))[:80]
        try:
            if cmd == "response_approve":
                await executor.approve(job_id, actor=str(msg.get("principal") or "operator"))
                await asyncio.to_thread(_run_response_job, executor, job_id)
            elif cmd == "response_deny":
                await executor.deny(job_id, actor=str(msg.get("principal") or "operator"),
                                    reason=str(msg.get("reason", ""))[:200])
            elif cmd == "response_rollback":
                await executor.rollback(job_id, actor=str(msg.get("principal") or "operator"),
                                        reason="người vận hành yêu cầu gỡ")
        except (TransitionError, ValueError) as exc:
            logger.warning("Thao tác phản ứng %s trên %s bị từ chối: %s", cmd, job_id, exc)

        if cmd == "response_job_detail" and job_id:
            await ipc.broadcast("response_job_detail", {
                "job_id": job_id,
                "job": (jobs_store.get(job_id).to_dict() if jobs_store.get(job_id) else None),
                "transitions": jobs_store.transitions(job_id),
                "verifications": jobs_store.verifications(job_id),
            })
        else:
            await ipc.broadcast("response_jobs", {"jobs": jobs_store.list_jobs()})
    elif cmd in {"set_response_kill_switch", "response_kill_switch_now"}:
        from shield.response.executor import (
            RESPONSE_KILL_SWITCH_ENV,
            response_automation_killed,
        )

        if cmd == "set_response_kill_switch":
            enabled = bool(msg.get("enabled", False))
            os.environ[RESPONSE_KILL_SWITCH_ENV] = "1" if enabled else "0"
            store.set_baseline("response_kill_switch", "1" if enabled else "0")
            store.add_audit_log("set_response_kill_switch", {"enabled": enabled},
                                "principal=" + str(msg.get("principal") or "operator"))
            logger.warning("Công tắc dừng phản ứng: %s",
                           "BẬT (không hành động nào được áp)" if enabled else "tắt")
        await ipc.broadcast("response_kill_switch",
                            {"enabled": response_automation_killed()})
    elif cmd in {"set_ai_kill_switch", "ai_kill_switch_now"}:
        # Kill switch nằm ở BIẾN MÔI TRƯỜNG của tiến trình agent, và được đọc
        # lại mỗi lần kiểm. Nhờ vậy nó có tác dụng NGAY, không cần khởi động
        # lại — người vận hành bật nó lúc đang có sự cố, đúng lúc họ không
        # muốn khởi động lại gì cả.
        from shield.ai.capability import KILL_SWITCH_ENV, ai_tools_killed

        if cmd == "set_ai_kill_switch":
            enabled = bool(msg.get("enabled", False))
            os.environ[KILL_SWITCH_ENV] = "1" if enabled else "0"
            # Ghi ra baseline để lần khởi động sau vẫn nhớ: một công tắc an
            # toàn quên mất mình đang bật là một công tắc không dùng được.
            store.set_baseline("ai_kill_switch", "1" if enabled else "0")
            store.add_audit_log("set_ai_kill_switch", {"enabled": enabled},
                                "principal=" + str(msg.get("principal") or "operator"))
            logger.warning("Kill switch AI: %s", "BẬT (mọi tool bị chặn)" if enabled else "tắt")
        await ipc.broadcast("ai_kill_switch", {"enabled": ai_tools_killed()})
    elif cmd in {"chat_open", "chat_send", "chat_history"}:
        # Hỏi đáp gắn vào MỘT sự cố. Không có lệnh nào nhận câu hỏi tự do mà
        # không kèm `incident_id`: phạm vi là một phần của lệnh, không phải một
        # quy ước người gọi phải nhớ.
        incident_id = str(msg.get("incident_id", ""))[:64]
        if not incident_id:
            return
        try:
            locale = "en" if str(msg.get("locale", "vi")).startswith("en") else "vi"
            if cmd == "chat_send":
                question = str(msg.get("question", ""))[:1000]
                payload = await asyncio.to_thread(chat_send, store, incident_id,
                                                  question, locale)
            else:
                payload = await asyncio.to_thread(chat_history, store, incident_id,
                                                  locale)
        except Exception as exc:  # noqa: BLE001 — hỏi đáp không được kéo agent xuống
            logger.warning("Hỏi đáp %s thất bại: %s", incident_id, exc)
            payload = {"status": "failed", "session_id": "", "messages": []}
        payload["incident_id"] = incident_id
        await ipc.broadcast("chat_state", payload)

    elif cmd == "investigate_incident":
        # AI analyst Level 0 (kế hoạch 2.0 Phase 2): CHỈ ĐỌC.
        #
        # Chạy trong thread riêng và nuốt mọi lỗi: nếu một lượt điều tra làm
        # đổ vòng lặp lệnh, thì việc BẬT phân tích trở thành nguyên nhân làm
        # hỏng phần còn lại của Shield — đúng thứ gate Phase 2 cấm.
        incident_id = str(msg.get("incident_id", ""))[:64]
        if not incident_id:
            return
        try:
            payload = await run_investigation(store, incident_id)
        except Exception as exc:  # noqa: BLE001 — phân tích không được kéo agent xuống
            logger.warning("Điều tra %s thất bại: %s", incident_id, exc)
            payload = {"incident_id": incident_id, "hypotheses": [],
                       "errors": [f"{type(exc).__name__}: {exc}"]}
        await ipc.broadcast("investigation_result", payload)
    elif cmd == "set_ai_explanation":
        # Bật/tắt phần giải thích. KHÔNG chọn model, KHÔNG sửa đường dẫn,
        # KHÔNG nhận prompt — chỉ một boolean.
        enabled = bool(msg.get("enabled", False))
        await asyncio.to_thread(store.set_baseline, EXPLANATION_OPT_IN_KEY,
                                "1" if enabled else "0")
        store.add_audit_log("ai_explanation", {"enabled": enabled}, "OK")
        await ipc.broadcast("ai_explanation_state", {
            "enabled": enabled,
            "provider_configured": os.environ.get("SHIELD_AI_PROVIDER", "disabled"),
        })
    elif cmd == "get_ai_explanation_state":
        await ipc.broadcast("ai_explanation_state", {
            "enabled": await asyncio.to_thread(_explanation_opt_in, store),
            "provider_configured": os.environ.get("SHIELD_AI_PROVIDER", "disabled"),
        })
    elif cmd == "set_log_export":
        # Đường dẫn này đến từ giao diện và đi vào một tiến trình chạy root.
        # Toàn bộ việc kiểm nằm ở log_export.validate_directory; ở đây chỉ
        # chuyển lỗi thành câu người dùng đọc được, KHÔNG nới lỏng gì.
        from shield.agent.log_export import ExportConfig, ExportPathError, LogExporter, validate_directory

        raw = {
            "enabled": bool(msg.get("enabled", False)),
            "directory": str(msg.get("directory", ""))[:4096],
            "max_mb": msg.get("max_mb", 1024),
            "include_events": bool(msg.get("include_events", True)),
            "include_alerts": bool(msg.get("include_alerts", True)),
        }
        config = ExportConfig.from_dict(raw)
        error = ""
        error_code = error_detail = ""
        if config.enabled:
            try:
                await asyncio.to_thread(validate_directory, config.directory)
            except ExportPathError as exc:
                error, error_code, error_detail = str(exc), exc.code, exc.detail
        if error:
            # KHÔNG lưu cấu hình hỏng. Lưu rồi báo lỗi nghĩa là lần khởi động
            # sau Shield lại thử đúng đường dẫn đó và lại hỏng, âm thầm.
            await ipc.broadcast("log_export_status", {
                **config.to_dict(), "active": False, "last_error": error,
                "last_error_code": error_code, "last_error_detail": error_detail,
            })
            return
        await asyncio.to_thread(store.set_log_export_config, config.to_dict())
        exporter = LogExporter(config)
        exporter_box["exporter"].close()
        exporter_box["exporter"] = exporter
        store.add_audit_log("set_log_export",
                            {"enabled": config.enabled, "directory": config.directory,
                             "max_mb": config.max_bytes // 1024 ** 2},
                            "OK")
        logger.warning("Xuất log: %s -> %s (hạn mức %d MB)",
                       "BẬT" if config.enabled else "TẮT",
                       config.directory or "(chưa chọn)", config.max_bytes // 1024 ** 2)
        await ipc.broadcast("log_export_status", _log_export_status(exporter_box, live))
    elif cmd == "get_log_export_status":
        await ipc.broadcast("log_export_status", _log_export_status(exporter_box, live))
    elif cmd == "reset_scan_session":
        # Quên thiết bị đã phát hiện rồi quét lại. Không đụng event/alert/ledger:
        # quên MÔ TẢ một thiết bị khác hẳn với xoá lịch sử những gì nó đã làm.
        raw_days = msg.get("older_than_days")
        try:
            older_than_days = float(raw_days) if raw_days not in (None, "", "all") else None
        except (TypeError, ValueError):
            logger.warning("reset_scan_session: older_than_days không hợp lệ: %r", raw_days)
            return
        if older_than_days is not None and not 0 < older_than_days <= 3650:
            logger.warning("reset_scan_session: khoảng thời gian ngoài giới hạn")
            return
        result = await asyncio.to_thread(store.reset_scan_session, older_than_days)
        logger.warning("Làm mới phiên quét: quên %d thiết bị (%s)",
                       result["devices_removed"],
                       "tất cả" if older_than_days is None else f"cũ hơn {older_than_days} ngày")
        await ipc.broadcast("scan_session_reset", {
            "devices_removed": result["devices_removed"],
            "identities_removed": result["identities_removed"],
        })
        await ipc.broadcast("devices_updated", {"reason": "scan_session_reset"})

    elif cmd == "trust_device":
        mac = str(msg.get("mac", "")).lower()
        if not _MAC_RE.fullmatch(mac):
            logger.warning("trust_device: MAC không hợp lệ: %r", mac)
            return
        store.add_trusted(mac, note="đánh dấu tin cậy từ UI")
        store.add_audit_log("trust_device", {"mac": mac}, "SUCCESS")
        await ipc.broadcast("devices_updated", {"reason": "trust"})
        logger.info("Đã tin cậy thiết bị %s", mac)

    elif cmd == "untrust_device":
        mac = str(msg.get("mac", "")).lower()
        if not _MAC_RE.fullmatch(mac):
            await ipc.send_to(client_id, "command_error", {"error": "invalid MAC address"})
            return
        store.remove_trusted(mac)
        store.add_audit_log("untrust_device", {"mac": mac}, "SUCCESS")
        await ipc.broadcast("devices_updated", {"reason": "untrust"})

    elif cmd == "update_device_metadata":
        try:
            device_id = str(msg.get("device_id", ""))
            store.update_device_metadata(
                device_id,
                display_name=str(msg.get("display_name", "")),
                owner_label=str(msg.get("owner_label", "")),
                location=str(msg.get("location", "")),
                purpose=str(msg.get("purpose", "")),
                criticality=str(msg.get("criticality", "Normal")),
            )
            store.add_audit_log("update_device_metadata", {"device_id": device_id}, "SUCCESS")
            await ipc.broadcast("devices_updated", {"reason": "metadata"})
        except ValueError as exc:
            await ipc.send_to(client_id, "command_error", {"error": str(exc)})

    elif cmd == "merge_devices":
        try:
            primary = str(msg.get("primary_id", ""))
            secondary = str(msg.get("secondary_id", ""))
            store.merge_device_identities(primary, secondary)
            store.add_audit_log("merge_devices", {"primary": primary, "secondary": secondary}, "SUCCESS")
            await ipc.broadcast("devices_updated", {"reason": "merge"})
        except ValueError as exc:
            await ipc.send_to(client_id, "command_error", {"error": str(exc)})

    elif cmd == "split_device":
        try:
            device_id = str(msg.get("device_id", ""))
            mac = str(msg.get("mac", "")).lower()
            if not _MAC_RE.fullmatch(mac):
                raise ValueError("invalid MAC address")
            new_id = store.split_device_identity(device_id, mac)
            store.add_audit_log("split_device", {"source": device_id, "new": new_id, "mac": mac}, "SUCCESS")
            await ipc.broadcast("devices_updated", {"reason": "split"})
        except ValueError as exc:
            await ipc.send_to(client_id, "command_error", {"error": str(exc)})

    elif cmd == "set_gateway_baseline":
        gw_ip = str(msg.get("gw_ip", ""))
        gw_mac = str(msg.get("gw_mac", "")).lower()
        if not _MAC_RE.match(gw_mac):
            logger.warning("set_gateway_baseline: MAC không hợp lệ: %r", gw_mac)
            return
        store.set_baseline(BASELINE_GW_IP, gw_ip)
        store.set_baseline(BASELINE_GW_MAC, gw_mac)
        store.mark_gateway_device(gw_ip)
        await ipc.broadcast("devices_updated", {"reason": "gateway"})
        logger.info("Baseline gateway: %s -> %s", gw_ip, gw_mac)

    elif cmd == "pin_gateway_arp":
        gw_ip = store.get_baseline(BASELINE_GW_IP)
        gw_mac = store.get_baseline(BASELINE_GW_MAC)
        if not gw_ip or not gw_mac:
            logger.warning("pin_gateway_arp: chưa có baseline gateway, bỏ qua")
            return
        iface = interface or await asyncio.to_thread(detect_interface)
        ok, result = await actions.pin_gateway_arp(gw_ip, gw_mac, iface)
        store.add_audit_log(
            "pin_gateway_arp", {"gw_ip": gw_ip, "gw_mac": gw_mac, "interface": iface}, result
        )
        logger.info("pin_gateway_arp %s: %s", "OK" if ok else "THẤT BẠI", result)

    elif cmd == "block_ip":
        ip = str(msg.get("ip", ""))
        ok, result = await run_privileged_action(privileged_client, "block_ip", {"ip": ip})
        store.add_audit_log("block_ip", {"ip": ip}, result)
        if ok:
            store.record_block("ip", ip, ttl_hours=24)
            await ipc.broadcast("blocks_updated", {"blocks": store.list_active_blocks()})
        logger.info("block_ip %s: %s", "OK" if ok else "THẤT BẠI", result)

    elif cmd == "unblock_ip":
        ip = str(msg.get("ip", ""))
        ok, result = await run_privileged_action(privileged_client, "unblock_ip", {"ip": ip})
        store.add_audit_log("unblock_ip", {"ip": ip}, result)
        if ok:
            store.remove_block("ip", ip)
            await ipc.broadcast("blocks_updated", {"blocks": store.list_active_blocks()})
        logger.info("unblock_ip %s: %s", "OK" if ok else "THẤT BẠI", result)

    elif cmd == "block_mac":
        mac = str(msg.get("mac", "")).lower()
        ok, result = await run_privileged_action(privileged_client, "block_mac", {"mac": mac})
        store.add_audit_log("block_mac", {"mac": mac}, result)
        if ok:
            store.record_block("mac", mac, ttl_hours=24)
            await ipc.broadcast("blocks_updated", {"blocks": store.list_active_blocks()})
        logger.info("block_mac %s: %s", "OK" if ok else "THẤT BẠI", result)

    elif cmd == "unblock_mac":
        mac = str(msg.get("mac", "")).lower()
        ok, result = await run_privileged_action(privileged_client, "unblock_mac", {"mac": mac})
        store.add_audit_log("unblock_mac", {"mac": mac}, result)
        if ok:
            store.remove_block("mac", mac)
            await ipc.broadcast("blocks_updated", {"blocks": store.list_active_blocks()})
        logger.info("unblock_mac %s: %s", "OK" if ok else "THẤT BẠI", result)

    elif cmd == "snapshot_state":
        ok, result = await actions.snapshot_state()
        store.add_audit_log("snapshot_state", {}, result)
        logger.info("snapshot_state %s: %s", "OK" if ok else "THẤT BẠI", result)

    elif cmd == "watch_device":
        ip = str(msg.get("ip", ""))
        mac = msg.get("mac")
        if not _IP_RE.match(ip):
            logger.warning("watch_device: IP không hợp lệ: %r", ip)
            return
        if not monitoring.allows("capture"):
            logger.info("watch_device %s bị bỏ qua: ghi lưu lượng đang tạm dừng", ip)
            await ipc.send_to(client_id, "watch_status",
                              {"ip": ip, "ok": False, "paused": True})
            return
        started = await traffic_manager.watch(ip, mac)
        logger.info("watch_device %s: %s", ip, "bắt đầu" if started else "đã theo dõi từ trước")

    elif cmd == "unwatch_device":
        ip = str(msg.get("ip", ""))
        if not _IP_RE.match(ip):
            logger.warning("unwatch_device: IP không hợp lệ: %r", ip)
            return
        stopped = await traffic_manager.unwatch(ip)
        logger.info("unwatch_device %s: %s", ip, "đã dừng" if stopped else "không tìm thấy phiên")

    elif cmd == "pause_monitoring":
        # Công tắc tắt/tạm dừng ngay trong app — không cần systemctl.
        scope = str(msg.get("scope", ALL))
        raw_duration = msg.get("duration_s")
        try:
            duration = None if raw_duration in (None, "", 0) else float(raw_duration)
            if duration is not None:
                duration = max(1.0, min(duration, MAX_PAUSE_S))
            state = monitoring.pause(scope, duration, str(msg.get("reason", ""))[:200])
        except (TypeError, ValueError) as exc:
            logger.warning("pause_monitoring không hợp lệ: %s", exc)
            await ipc.send_to(client_id, "monitoring_state",
                              {"ok": False, "error": str(exc), **monitoring.state().to_dict()})
            return
        # Dừng ngay thứ đang chạy, không đợi vòng lặp kế tiếp: phiên tcpdump
        # và tarpit đang mở phải im lặng ngay khi người dùng bấm nút.
        if not monitoring.allows("capture"):
            await traffic_manager.stop_all()
            await tarpit_manager.stop_all()
        logger.warning("Giám sát TẠM DỪNG (%s) bởi %s — lý do: %s",
                       scope, principal, state.reason or "không nêu")
        await broadcast_monitoring_state(ipc, monitoring)

    elif cmd == "resume_monitoring":
        scope = str(msg.get("scope", ALL))
        try:
            monitoring.resume(scope)
        except ValueError as exc:
            logger.warning("resume_monitoring không hợp lệ: %s", exc)
            return
        logger.warning("Giám sát BẬT LẠI (%s) bởi %s", scope, principal)
        await broadcast_monitoring_state(ipc, monitoring)

    elif cmd in {"expert_search_events", "expert_get_event"}:
        # ĐƯỜNG ĐỌC DUY NHẤT cho Expert Evidence.
        #
        # Giao diện không mở database và không viết SQL — nó gửi hai lệnh này.
        # `EvidenceQueries` đã mang sẵn mọi thứ mà một đường đọc phải có: trần
        # cứng, ngân sách thời gian, che bí mật bằng bộ luật chung, và nhật ký
        # truy vấn. Dựng một lớp đọc riêng cho chuyên gia nghĩa là dựng lại cả
        # bốn thứ đó, rồi để chúng lệch nhau.
        #
        # Không đi qua Capability broker: đó là cổng cho MODEL, và ở đây không
        # có model nào. Người dùng đã qua kiểm quyền của chính socket IPC.
        from shield.evidence.queries import EvidenceQueries, QueryTimeout

        queries = EvidenceQueries(store.conn, caller=f"expert:{principal}")
        try:
            if cmd == "expert_get_event":
                payload = {"event": queries.get_event(str(msg.get("event_id", "")))}
            else:
                payload = queries.search_events(
                    start_time=msg.get("start_time"), end_time=msg.get("end_time"),
                    kind=str(msg.get("kind", "")), source=str(msg.get("source", "")),
                    origin=str(msg.get("origin", "")),
                    event_id=str(msg.get("event_id", "")),
                    incident_id=str(msg.get("incident_id", "")),
                    alert_id=msg.get("alert_id"),
                    filters=msg.get("filters") or {},
                    limit=msg.get("limit", 100), cursor=str(msg.get("cursor", "")))
        except (ValueError, TypeError, QueryTimeout) as exc:
            # Fail closed: bộ lọc hỏng thì TỪ CHỐI, không âm thầm bỏ qua điều
            # kiện rồi trả về một trang trông có vẻ đúng.
            await ipc.send_to(client_id, "command_error", {"cmd": cmd, "error": str(exc)})
            return
        # Đọc không phải hành động, nhưng nó vẫn là DỮ LIỆU RỜI KHỎI kho. Ghi
        # phạm vi và số dòng — KHÔNG ghi nội dung.
        last = queries.audit.entries[-1] if queries.audit.entries else {}
        store.add_audit_log(cmd, {"principal": principal,
                                  "scope": last.get("params", {}),
                                  "rows": last.get("rows", 0)},
                            f"{last.get('rows', 0)} dòng trong {last.get('elapsed_s', 0):.3f}s")
        payload["request_id"] = msg.get("request_id")
        await ipc.send_to(client_id, cmd + "_result", payload)

    elif cmd == "incident_set_state":
        # Đóng/mở lại một sự việc từ UI (mục B5). Trước đây store có hàm này
        # nhưng không có đường nào gọi tới — sự việc mở ra rồi ở mãi đó.
        incident_id = str(msg.get("incident_id", ""))
        state = str(msg.get("state", ""))
        try:
            changed = store.set_incident_state(incident_id, state)
        except ValueError as exc:
            await ipc.send_to(client_id, "command_error", {"cmd": cmd, "error": str(exc)})
            return
        store.add_audit_log("incident_set_state",
                            {"incident_id": incident_id, "state": state, "principal": principal},
                            "ok" if changed else "không tìm thấy sự việc")
        await ipc.broadcast("incidents_updated", {"incidents": store.list_incidents(limit=100)})

    elif cmd == "renew_isolation":
        # Gia hạn một lệnh cách ly đang chạy. Không có lệnh này thì dead-man
        # switch luôn tự gỡ sau ttl và người vận hành không có cách nào giữ
        # máy ở trạng thái cách ly lâu hơn ngoài việc cách ly lại từ đầu.
        target = str(msg.get("target", ""))
        try:
            ttl = max(30, min(int(msg.get("ttl_s", 300)), 3600))
        except (TypeError, ValueError):
            ttl = 300
        renewed = response_executor.dead_man.renew(target, ttl) if response_executor.dead_man else False
        store.add_audit_log("renew_isolation", {"target": target, "ttl_s": ttl, "principal": principal},
                            "ok" if renewed else "không có lệnh cách ly nào đang chạy cho đích này")
        logger.warning("Gia hạn cách ly %s: %s", target, "OK" if renewed else "KHÔNG CÓ")
        await ipc.send_to(client_id, "isolation_state", {
            "target": target, "renewed": renewed,
            "armed": sorted(response_executor.dead_man.armed()) if response_executor.dead_man else [],
        })

    elif cmd == "monitoring_status_now":
        await ipc.send_to(client_id, "monitoring_state", monitoring.state().to_dict())

    elif cmd == "shutdown_agent":
        # Tắt hẳn từ trong app. Ghi audit TRƯỚC khi tắt — nếu ghi sau thì
        # agent đã chết, và Guardian sẽ tưởng đây là một vụ giết tiến trình.
        reason = str(msg.get("reason", ""))[:200]
        store.add_audit_log("shutdown_agent", {"reason": reason, "principal": principal}, "requested")
        store.add_forensic_record("switch", {"action": "shutdown_agent", "reason": reason,
                                             "principal": principal, "ts": time.time()})
        logger.warning("TẮT AGENT theo yêu cầu từ app bởi %s — lý do: %s", principal, reason or "không nêu")
        await ipc.broadcast("agent_shutting_down", {"reason": reason, "ts": time.time()})
        SHUTDOWN.set()

    elif cmd == "discover_now":
        asyncio.create_task(run_quick_scan(store, event_bus, ipc, interface))

    elif cmd == "discover_deep":
        asyncio.create_task(run_deep_scan(store, event_bus, ipc, interface))

    elif cmd == "self_port_scan":
        host = str(msg.get("host", ""))
        asyncio.create_task(run_self_audit(host, store, ipc))

    elif cmd == "add_authorized_range":
        cidr = str(msg.get("cidr", "")).strip()
        note = str(msg.get("note", "")).strip()
        ok, result = actions.validate_authorized_cidr(cidr)
        if not ok:
            logger.warning("add_authorized_range: %s", result)
            await ipc.broadcast("authorized_range_error", {"error": result})
            return
        if not note:
            logger.warning("add_authorized_range: thiếu lý do/căn cứ cấp phép, từ chối")
            await ipc.broadcast(
                "authorized_range_error",
                {
                    "error_key": "err.missing_note",
                    "error": "Cần ghi rõ lý do/căn cứ cấp phép trước khi thêm",
                },
            )
            return
        store.add_authorized_range(result, note)
        store.add_audit_log("add_authorized_range", {"cidr": result, "note": note}, "OK")
        logger.info("Đã thêm dải được cấp phép: %s (%s)", result, note)
        await ipc.broadcast("authorized_ranges_updated", {"ranges": store.list_authorized_ranges()})

    elif cmd == "remove_authorized_range":
        cidr = str(msg.get("cidr", "")).strip()
        store.remove_authorized_range(cidr)
        store.add_audit_log("remove_authorized_range", {"cidr": cidr}, "OK")
        logger.info("Đã gỡ dải được cấp phép: %s", cidr)
        await ipc.broadcast("authorized_ranges_updated", {"ranges": store.list_authorized_ranges()})

    elif cmd == "scan_authorized_range":
        cidr = str(msg.get("cidr", "")).strip()
        try:
            target = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("scan_authorized_range: cidr không hợp lệ %r", cidr)
            return
        authorized = any(
            str(target) == r["cidr"] or target.subnet_of(ipaddress.ip_network(r["cidr"], strict=False))
            for r in store.list_authorized_ranges()
        )
        if not authorized:
            logger.warning("scan_authorized_range: %s KHÔNG nằm trong danh sách cấp phép — từ chối", cidr)
            store.add_audit_log("scan_authorized_range_denied", {"cidr": cidr}, "Chưa được cấp phép")
            return
        asyncio.create_task(run_range_scan(str(target), store, event_bus, ipc))

    elif cmd == "set_router_backend":
        kind = str(msg.get("backend_type", "disabled"))
        config: dict = {"type": kind}
        if kind == "ssh_conntrack":
            host = str(msg.get("host", "")).strip()
            if not host:
                logger.warning("set_router_backend: thiếu host")
                await ipc.broadcast(
                    "router_backend_error",
                    {"error_key": "err.missing_router_host", "error": "Thiếu địa chỉ router"},
                )
                return
            config.update(
                host=host,
                user=str(msg.get("user", "root")).strip() or "root",
                port=int(msg.get("port", 22) or 22),
                key_path=str(msg.get("key_path", "")).strip() or None,
            )
        elif kind == "custom_script":
            path = str(msg.get("path", "")).strip()
            if not path:
                logger.warning("set_router_backend: thiếu đường dẫn script")
                await ipc.broadcast(
                    "router_backend_error",
                    {"error_key": "err.missing_script_path", "error": "Thiếu đường dẫn script"},
                )
                return
            config.update(path=path)
        elif kind != "disabled":
            logger.warning("set_router_backend: loại không hỗ trợ %r", kind)
            return
        store.set_baseline(ROUTER_BACKEND_CONFIG_KEY, json.dumps(config))
        store.add_audit_log("set_router_backend", config, "OK")
        logger.info("Đã cấu hình router backend: %s", kind)

    elif cmd == "poll_router_traffic_now":
        raw = store.get_baseline(ROUTER_BACKEND_CONFIG_KEY)
        config = json.loads(raw) if raw else {"type": "disabled"}
        lan_subnet = await asyncio.to_thread(detect_subnet, interface or await asyncio.to_thread(detect_interface))
        ok, msg2, hosts = await router_backends.poll(config, lan_subnet)
        if not ok:
            await ipc.broadcast("router_backend_error", {"error": msg2})
            return
        now_ts = time.time()
        for h in hosts:
            store.upsert_router_traffic(h["ip"], h.get("mac"), h["rx_bytes"], h["tx_bytes"])
        await ipc.broadcast(
            "router_traffic_updated",
            {"hosts": [{**h, "rx_rate": 0.0, "tx_rate": 0.0} for h in hosts], "ts": now_ts},
        )

    elif cmd == "detect_gateway_ip_now":
        gw_ip = await asyncio.to_thread(detect_gateway_ip)
        await ipc.broadcast("gateway_ip_detected", {"gw_ip": gw_ip})
        logger.info("detect_gateway_ip_now: %s", gw_ip or "không dò được")

    elif cmd == "set_evasion":
        enabled = bool(msg.get("enabled", False))
        if enabled and not interface:
            await ipc.broadcast(
                "evasion_error",
                {"error_key": "err.no_interface_for_evasion", "error": "Không xác định được interface để đổi MAC/IP"},
            )
            return
        if "interval_s" in msg:
            try:
                interval = int(msg["interval_s"])
            except (TypeError, ValueError):
                interval = EVASION_DEFAULT_INTERVAL_S
            interval = min(EVASION_MAX_INTERVAL_S, max(EVASION_MIN_INTERVAL_S, interval))
            store.set_baseline(EVASION_INTERVAL_KEY, str(interval))
        store.set_baseline(EVASION_ENABLED_KEY, "1" if enabled else "0")
        store.add_audit_log(
            "set_evasion", {"enabled": enabled, "interface": interface},
            "BẬT" if enabled else "TẮT",
        )
        logger.warning(
            "set_evasion: %s (interface=%s) — xử lý thật diễn ra trong evasion_loop",
            "BẬT" if enabled else "TẮT", interface,
        )
        await ipc.broadcast("evasion_status", await collect_evasion_status(store, interface))

    elif cmd == "evasion_status_now":
        await ipc.broadcast("evasion_status", await collect_evasion_status(store, interface))

    elif cmd == "set_tarpit":
        enabled = bool(msg.get("enabled", False))
        if "ports" in msg:
            ports = tarpit.parse_port_list(str(msg.get("ports", "")))
            if not ports:
                await ipc.broadcast(
                    "tarpit_error",
                    {"error_key": "err.no_tarpit_ports", "error": "Chưa nhập cổng mồi hợp lệ nào"},
                )
                return
            store.set_baseline(TARPIT_PORTS_KEY, ",".join(str(p) for p in ports))
        store.set_baseline(TARPIT_ENABLED_KEY, "1" if enabled else "0")
        logger.warning(
            "set_tarpit: %s — xử lý thật diễn ra trong tarpit_loop", "BẬT" if enabled else "TẮT"
        )

    elif cmd == "tarpit_status_now":
        await ipc.broadcast(
            "tarpit_status",
            {
                "enabled": store.get_baseline(TARPIT_ENABLED_KEY) == "1",
                "ports": tarpit_manager.active_ports,
                "connections": tarpit_manager.list_connections(),
                "ts": time.time(),
            },
        )

    elif cmd == "dns_status_now":
        await ipc.broadcast("dns_status", await collect_dns_status(store))

    elif cmd == "dns_hijack_check":
        asyncio.create_task(run_dns_hijack_check(ipc, store))

    elif cmd == "set_dns_baseline":
        servers, _source = await dns_audit.read_resolvers()
        if not servers:
            await ipc.broadcast(
                "dns_error",
                {"error_key": "err.no_dns_servers", "error": "Chưa đọc được DNS server nào để lưu"},
            )
            return
        value = ",".join(sorted(servers))
        store.set_baseline(BASELINE_DNS_SERVERS, value)
        store.add_audit_log("set_dns_baseline", {"servers": value}, "OK")
        logger.info("Đã đặt baseline DNS: %s", value)
        await ipc.broadcast("dns_status", await collect_dns_status(store))

    elif cmd == "list_wifi_passwords":
        ok, msg2, networks = await actions.list_saved_wifi_passwords()
        store.add_audit_log("list_wifi_passwords", {}, msg2 if not ok else f"OK ({len(networks)} mạng)")
        # send_to chứ KHÔNG broadcast: payload chứa PSK plaintext, chỉ client
        # đã gửi lệnh mới được nhận. broadcast sẽ đẩy mật khẩu tới mọi UI đang
        # mở socket (user thứ hai trong group shield, fast user switching) mà
        # audit log không ghi lại được ai đã nhận.
        await ipc.send_to(
            client_id,
            "wifi_passwords_result",
            {"request_id": request_id, "ok": ok, "error": None if ok else msg2, "networks": networks},
        )

    elif cmd == "set_scan_schedule":
        enabled = bool(msg.get("enabled", False))
        days = [d for d in msg.get("days", []) if isinstance(d, int) and 0 <= d <= 6]
        run_time = str(msg.get("time", ""))
        if not _TIME_RE.match(run_time):
            logger.warning("set_scan_schedule: giờ không hợp lệ: %r", run_time)
            return
        store.set_baseline(SCAN_SCHEDULE_KEY, json.dumps({"enabled": enabled, "days": days, "time": run_time}))
        logger.info("Lịch quét sâu: enabled=%s days=%s time=%s", enabled, days, run_time)

    else:
        logger.warning("Lệnh không nằm trong allowlist: %r", cmd)


async def run_fake_injector(alert_bus: Bus, count: int = 10, interval_s: float = 1.0) -> None:
    """Sinh `count` alert giả để verify giai đoạn 0 (xem KE-HOACH-SHIELD.md mục 5)."""
    for i in range(count):
        rule_id, severity, title = random.choice(FAKE_RULES)
        alert = Alert(
            ts=now(),
            rule_id=rule_id,
            severity=severity,
            title=title,
            detail=f"Cảnh báo giả #{i + 1} để test đường ống agent -> UI",
            subject=f"fake-subject-{i % 4}",
            evidence={"note": "sinh bởi --inject-fake-events", "index": i},
            playbook=[],
        )
        await alert_bus.publish(alert)
        await asyncio.sleep(interval_s)
    logger.info("Đã inject %d alert giả.", count)


async def gateway_baseline_wizard_loop(store: Store, ipc: IpcServer) -> None:
    """Nếu chưa có baseline gateway, tự dò rồi lặp lại gợi ý cho UI xác nhận
    (wizard rút gọn của mục 2.1 — "MAC gateway hiện tại là X, đúng không?").

    Lặp lại (không chỉ gửi 1 lần) vì UI có thể kết nối sau khi agent đã dò
    xong. Không tự set baseline — chỉ người dùng xác nhận qua UI mới được
    set, vì baseline sai sẽ làm mọi detector MITM vô dụng.
    """
    if store.get_baseline(BASELINE_GW_MAC) is not None:
        return

    gw_ip = await asyncio.to_thread(detect_gateway_ip)
    if not gw_ip:
        logger.warning("Không tự dò được gateway IP — cần set_gateway_baseline thủ công")
        return
    gw_mac = await asyncio.to_thread(detect_gateway_mac, gw_ip)
    if not gw_mac:
        logger.warning(
            "Dò được gateway IP=%s nhưng chưa có MAC trong bảng ARP (ping router "
            "một lần rồi khởi động lại agent). Cần set_gateway_baseline thủ công.",
            gw_ip,
        )
        return

    logger.info("Gợi ý baseline gateway: %s -> %s (chờ UI xác nhận)", gw_ip, gw_mac)
    while store.get_baseline(BASELINE_GW_MAC) is None:
        await ipc.broadcast("baseline_needed", {"gw_ip": gw_ip, "gw_mac": gw_mac})
        await asyncio.sleep(15)



# ==========================================================================
# Hỏi đáp gắn vào MỘT sự cố (Incident Chat v0)
# ==========================================================================


# Đủ cho hai ô, mỗi ô <= `MAX_ANSWER_CHARS`, cộng khung JSON. Xem đo đạc
# trong báo cáo phase: 768 token chạm timeout 60 giây.
CHAT_OUTPUT_TOKENS = 384


def _localised(key: str, locale: str) -> str:
    """Chuỗi theo NGÔN NGỮ CỦA SỰ CỐ, không theo ngôn ngữ giao diện.

    `i18n.t()` đọc một biến toàn cục của tiến trình giao diện. Agent là tiến
    trình khác và có thể phục vụ nhiều client; lấy ngôn ngữ từ báo cáo là thứ
    duy nhất đúng ở đây.
    """
    from shield.ui.i18n import STRINGS

    vietnamese, english = STRINGS.get(key, (key, key))
    return english if str(locale).startswith("en") else vietnamese


def chat_gate(store, incident_id: str, locale: str = "vi") -> tuple[bool, str, dict]:
    """Hỏi đáp có dùng được cho sự cố này không. -> (được, lý do, báo cáo).

    KHÔNG có cổng AI ở đây, và đó là một sửa đổi có chủ ý ở 3.0.0a2.
    Cả năm ý định đều trả lời TẤT ĐỊNH từ báo cáo Shield tự dựng, nên bắt chúng
    chờ một công tắc đồng ý chạy model là giấu phân tích của chính Shield sau
    một quyết định không liên quan. Công tắc AI dành cho việc chạy model; nó
    không phải công tắc của phần phân tích tất định.

    Hệ quả cụ thể: máy chưa cài `llama-cpp-python` — kể cả ngay sau một lần
    nâng cấp gói vừa xoá nó — vẫn hỏi đáp được đầy đủ.

    Cổng cho việc CHẠY MODEL nằm ở `model_gate`, và ở 3.0.0a2 không ý định nào
    đi qua đó.
    """
    from shield.report.incident import build as build_incident_report

    # `locale` phải đi vào tận đây. Câu trả lời hỏi đáp được DỰNG THÀNH CHỮ ở
    # phía agent, khác báo cáo (trả về khoá để giao diện tự dịch) — nên nếu
    # không truyền ngôn ngữ xuống, người dùng giao diện tiếng Anh nhận về câu
    # trả lời tiếng Việt. Mặc định "vi" giữ nguyên hành vi cũ.
    report = build_incident_report(store, incident_id, locale=locale)
    if not report:
        return False, "ineligible", {}
    return True, "", report


def model_gate(store, report: dict) -> tuple[bool, str]:
    """Có được CHẠY MODEL cho sự cố này không. -> (được, lý do).

    Đúng bốn cổng như đường làm giàu, cùng thứ tự — kill switch, provider,
    đồng ý của người dùng, độ chín của kịch bản. Ở 3.0.0a2 không ý định nào gọi
    tới đây; hàm giữ lại vì hạ tầng model vẫn ở trong cây cho các bản sau.
    """
    from shield.ai.capability import ai_tools_killed
    from shield.report.scenarios import explanation_enabled

    if ai_tools_killed():
        return False, "disabled"
    if os.environ.get("SHIELD_AI_PROVIDER", "disabled") == "disabled":
        return False, "disabled"
    if not _explanation_opt_in(store):
        return False, "disabled"
    if not explanation_enabled(report["incident_type"]["scenario_code"]):
        return False, "ineligible"
    return True, ""


def chat_open(store, incident_id: str, locale: str = "vi") -> dict:
    """Mở (hoặc lấy lại) phiên hỏi đáp của một sự cố."""
    from shield.ai.chat import ChatStore

    allowed, reason, report = chat_gate(store, incident_id, locale)
    if not allowed:
        return {"status": reason, "session_id": "", "messages": []}
    configured = os.environ.get("SHIELD_AI_PROVIDER", "disabled")
    locale = str(report.get("locale", "vi"))
    key, _version = enrichment_key(store, incident_id, report, locale, configured)
    chat = ChatStore(store.conn)
    session_id = chat.open_session(incident_id=incident_id, locale=locale,
                                  evidence_fingerprint=key)
    return {"status": "ready", "session_id": session_id,
            "evidence_fingerprint": key,
            "messages": [_chat_message_view(m) for m in chat.transcript(session_id)]}


def _chat_message_view(message) -> dict:
    """Hình dạng AN TOÀN gửi cho giao diện. Không có gì ngoài những trường này."""
    return {"message_id": message.message_id, "role": message.role,
            "turn_index": message.turn_index, "question": message.question,
            "answer": message.answer, "limitations": message.limitations,
            "ref_ids": list(message.ref_ids), "status": message.status,
            "failure_code": message.failure_code}


def chat_send(store, incident_id: str, question: str,
              locale: str = "vi") -> dict:
    """Nhận câu hỏi, trả về NGAY. Suy luận diễn ra ở runner nền."""
    from shield.ai.chat import ChatStore
    from shield.ai.chat_answer import deterministic_answer
    from shield.ai.chat_intents import OUT_OF_SCOPE_CHAT
    from shield.ai.chat_router import route
    from shield.ai.chat_scope import ACTION_REQUEST, IN_SCOPE, classify

    allowed, reason, report = chat_gate(store, incident_id, locale)
    if not allowed:
        return {"status": reason, "session_id": "", "message": None}
    configured = os.environ.get("SHIELD_AI_PROVIDER", "disabled")
    locale = str(report.get("locale", locale))
    key, _version = enrichment_key(store, incident_id, report, locale, configured)
    chat = ChatStore(store.conn)
    session_id = chat.open_session(incident_id=incident_id, locale=locale,
                                  evidence_fingerprint=key)

    # Ánh xạ Ý ĐỊNH bằng luật TẤT ĐỊNH, trước mọi lượt suy luận.
    #
    # Model không bao giờ được hỏi "câu này hỏi gì". Đó đúng là phép thử phân
    # loại đã trượt ở tầng kịch bản (54,8% so với 100% của bảng tra), và hỏi
    # đáp mở đã trượt lần thứ hai theo cùng một kiểu: model lặp câu và trả lời
    # hai câu hỏi khác nhau y hệt nhau.
    intent_code = route(question)
    if intent_code == OUT_OF_SCOPE_CHAT:
        kind = classify(question)
        key_name = ("chat.answer.action_request" if kind == ACTION_REQUEST
                    else "chat.answer.out_of_scope_chat")
        message = chat.answer_now(session_id=session_id, question=question,
                                  answer=_localised(key_name, locale),
                                  evidence_fingerprint=key, intent=OUT_OF_SCOPE_CHAT)
        return {"status": "ready", "session_id": session_id,
                "scope": kind if kind != IN_SCOPE else OUT_OF_SCOPE_CHAT,
                "intent": OUT_OF_SCOPE_CHAT,
                "message": _chat_message_view(message) if message else None}

    # Ý định nào dữ liệu đã trả lời trọn vẹn thì KHÔNG gọi model.
    text, refs = deterministic_answer(intent_code, report, locale)
    if text:
        message = chat.answer_now(session_id=session_id, question=question,
                                  answer=text, evidence_fingerprint=key,
                                  intent=intent_code, ref_ids=refs)
        return {"status": "ready", "session_id": session_id, "scope": "deterministic",
                "intent": intent_code,
                "message": _chat_message_view(message) if message else None}

    # Tới đây nghĩa là ý định CẦN model. Ở 3.0.0a2 không ý định nào tới được,
    # nhưng cổng vẫn phải đứng đây cho bản sau — và nó là cổng DUY NHẤT.
    allowed_model, why_not = model_gate(store, report)
    if not allowed_model:
        return {"status": why_not, "session_id": session_id, "intent": intent_code,
                "message": None}
    message, why = chat.ask(session_id=session_id, question=question,
                            evidence_fingerprint=key, intent=intent_code)
    if message is None:
        return {"status": "rejected", "session_id": session_id, "reason": why,
                "message": None}
    return {"status": "pending", "session_id": session_id, "scope": "model",
            "intent": intent_code, "message": _chat_message_view(message)}


def chat_history(store, incident_id: str, locale: str = "vi") -> dict:
    """Đọc lại hội thoại. Đây cũng là đường UI thăm dò câu trả lời đang chờ."""
    return chat_open(store, incident_id, locale)


def _chat_context(store, report: dict, message) -> dict:
    """Ngữ cảnh TẤT ĐỊNH cho một lượt hỏi đáp.

    Chỉ những gì đã nằm trong báo cáo. Không truy vấn mới, không nhét cả cơ sở
    dữ liệu vào prompt: câu hỏi luôn về MỘT sự cố, và báo cáo của sự cố đó đã
    là toàn bộ những gì Shield tự đo được về nó.
    """
    from shield.ai.chat import MAX_HISTORY_TURNS, ChatStore

    chat = ChatStore(store.conn)
    history = [{"question": turn.question, "answer": turn.answer}
               for turn in chat.history_turns(message.session_id, MAX_HISTORY_TURNS)]
    return {
        "scenario_code": report["incident_type"]["scenario_code"],
        "family": report["incident_type"]["family"],
        "severity": report["severity"]["level"],
        "subject": report["affected_asset"]["subject"],
        "confirmed_facts": report["confirmed_facts"],
        "evidence_count": report["validated_evidence"]["count"],
        "limitations": [item["key"] for item in report["limitations"]],
        "epistemic_state": report.get("epistemic_state", "UNCONFIRMED"),
        "question": message.question,
        "intent": message.intent,
        "history": history,
    }


def _alert_tokens(store, ref_id: str) -> frozenset:
    """Giá trị chuẩn tắc mà MỘT ref bằng chứng chống lưng.

    Dựng từ chính cảnh báo sinh ra ref đó, bằng cùng bộ nhận dạng mà đường báo
    cáo dùng — nên "giá trị này có trong bằng chứng" ở đây và ở bộ kiểm đầu ra
    nghĩa giống hệt nhau.
    """
    from shield.report.template import allowed_values

    row = store.conn.execute(
        "SELECT severity,risk_score,subject,evidence FROM alerts "
        "WHERE json_extract(evidence,'$.event_id')=? LIMIT 1", (str(ref_id),)).fetchone()
    if row is None:
        return frozenset()
    try:
        evidence = json.loads(row[3] or "{}")
    except ValueError:
        evidence = {}
    return allowed_values({"severity": row[0], "risk_score": row[1],
                           "subject": row[2], "evidence": evidence}, ())


def citation_refs(store, report: dict, answer: str) -> list:
    """Ref bằng chứng chống lưng cho câu trả lời NÀY. Chiến lược (b).

    Ứng viên CHỈ đến từ tập ref đã kiểm của sự cố, nên một ref bịa hay ref của
    sự cố khác không có đường vào — model không hề được hỏi về ref.

    Ba nhánh:
      - khớp được ref cụ thể  -> đúng tập con đó
      - có nêu dữ kiện nhưng không quy được về ref nào -> toàn bộ tập đã kiểm
      - không nêu dữ kiện nào  -> rỗng, và đó là đúng: một câu giải thích thuần
        không có gì để trích dẫn.
    """
    refs = list(report.get("validated_evidence", {}).get("refs", []))
    text = str(answer or "")
    if not refs or not text:
        return []
    matched = [ref for ref in refs
               if any(token and token in text for token in _alert_tokens(store, ref))]
    if matched:
        return matched
    alert = {"severity": report["severity"]["level"],
             "risk_score": report["severity"]["risk_score"],
             "subject": report["affected_asset"]["subject"],
             "evidence": report["confirmed_facts"]}
    from shield.report.template import allowed_values

    if any(token and token in text for token in allowed_values(alert, ())):
        return refs
    return []


async def execute_chat_job(store, message) -> tuple[dict | None, str]:
    """Chạy MỘT lượt hỏi đáp. -> (câu trả lời an toàn, mã hỏng).

    Mọi cổng được kiểm LẠI ở đây: giữa lúc người dùng bấm gửi và lúc job chạy
    có thể đã qua vài phút, và kill switch tồn tại để bấm giữa chừng.
    """
    from shield.ai.chat import MAX_ANSWER_CHARS
    from shield.ai.local_model import LocalModelAnalyst
    from shield.ai.model_config import from_environment
    from shield.ai.worker.protocol import WorkerRequest
    from shield.ai.worker.supervisor import WorkerFailure
    from shield.report.incident import build as build_incident_report
    from shield.report.template import allowed_values, clean_prose, epistemic_state

    allowed, reason, report = chat_gate(store, message.incident_id)
    if not allowed:
        return None, "provider_unavailable"
    allowed_model, _why = model_gate(store, report)
    if not allowed_model:
        return None, ("kill_switch" if _ai_killed_now() else "provider_unavailable")

    configured = os.environ.get("SHIELD_AI_PROVIDER", "disabled")
    locale = str(report.get("locale", message.locale))
    current, _version = await asyncio.to_thread(
        enrichment_key, store, message.incident_id, report, locale, configured)
    if current != message.evidence_fingerprint:
        # Bằng chứng đã đổi từ lúc đặt câu hỏi. Trả lời theo dữ liệu cũ là nói
        # về một thứ không còn tồn tại.
        return None, ""

    try:
        config = from_environment()
    except Exception:  # noqa: BLE001
        config = None
    if config is None:
        return None, "provider_unavailable"
    # `dataclasses.replace`, KHÔNG phải `hasattr(config, "replace")`:
    # `ModelConfig` là dataclass đóng băng và không có phương thức đó, nên một
    # nhánh dự phòng kiểu ấy sẽ lặng lẽ giữ `mode="explanation_only"`. Worker
    # khi đó chạy nhánh giải thích, trả về ba ô báo cáo, và `answer` rỗng —
    # hỏng theo đúng kiểu im lặng đã gặp ở 3C.
    # Trần SINH của lượt hỏi đáp, không chỉ đổi chế độ.
    #
    # Đo được: với 768 token đầu ra, một câu hỏi mất >60 giây và chạm timeout
    # của worker — hỏng, và hỏng theo kiểu tốn đúng một phút để không nhận được
    # gì. Hợp đồng chat là hai tới bốn câu, và `clean_prose` cắt ở
    # `MAX_ANSWER_CHARS` nữa, nên phần lớn số token đó bị vứt đi sau khi đã trả
    # tiền để sinh ra. Cắt ở nguồn thay vì cắt ở đích.
    config = dataclasses.replace(config, mode="chat",
                                 max_output_tokens=CHAT_OUTPUT_TOKENS)

    context = await asyncio.to_thread(_chat_context, store, report, message)
    analyst = LocalModelAnalyst(config)
    request = WorkerRequest(request_id=message.message_id[:64], facts=(context,),
                            target_locale=locale, deadline_s=config.timeout_s)
    try:
        response = await analyst.supervisor.request(request)
    except WorkerFailure as exc:
        return None, _job_failure_code(exc.code)
    if not response.ok:
        return None, _job_failure_code(response.failure_code)

    # Bằng chứng có thể đã đổi TRONG LÚC suy luận. Kiểm lại lần cuối.
    fresh = await asyncio.to_thread(build_incident_report, store, message.incident_id)
    again, _v = await asyncio.to_thread(
        enrichment_key, store, message.incident_id, fresh,
        str(fresh.get("locale", locale)), configured)
    if again != message.evidence_fingerprint:
        return None, ""

    # CÙNG bộ kiểm mà đường báo cáo dùng. Không có phiên bản nhẹ hơn cho chat.
    alert = {"severity": fresh["severity"]["level"],
             "risk_score": fresh["severity"]["risk_score"],
             "subject": fresh["affected_asset"]["subject"],
             "evidence": fresh["confirmed_facts"]}
    state = epistemic_state(evidence_refs=fresh["validated_evidence"]["refs"])
    allowed_tokens = allowed_values(alert, fresh["validated_evidence"]["refs"])
    from shield.ai.chat_intents import intent_of

    intent = intent_of(message.intent)
    cap = intent.max_answer_chars if intent else MAX_ANSWER_CHARS
    answer = clean_prose(response.result.get("answer", ""), state=state,
                         allowed=allowed_tokens, max_chars=cap)
    limitations = clean_prose(response.result.get("limitations", ""), state=state,
                              allowed=allowed_tokens, max_chars=MAX_ANSWER_CHARS)
    if not answer:
        return None, "validation_failed"
    refs = ([] if intent and not intent.attach_refs
            else await asyncio.to_thread(citation_refs, store, fresh, answer))
    return {"answer": answer, "limitations": limitations, "ref_ids": refs}, ""


def _ai_killed_now() -> bool:
    from shield.ai.capability import ai_tools_killed

    return ai_tools_killed()

async def main_async(args: argparse.Namespace) -> None:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Interface Shield tự sniff — dò 1 LẦN DUY NHẤT ở đây, TRƯỚC khi tạo bất
    # kỳ thứ gì dùng tới interface, rồi truyền own_iface đi khắp nơi. Trước
    # đây own_iface (dùng để lọc LOCAL_PROMISC_MODE) và args.interface thô
    # (truyền thẳng cho TrafficManager/arp_sniffer/conn_watch/...) là 2 nguồn
    # lệch nhau khi args.interface để trống (cách dùng phổ biến nhất): trên
    # máy nhiều interface (Wi-Fi+Ethernet+VPN+Docker), scapy có thể tự chọn
    # khác với `ip route get`, khiến Shield tự báo LOCAL_PROMISC_MODE về
    # chính mình.
    own_iface = args.interface or await asyncio.to_thread(detect_interface)
    own_interfaces = {own_iface} if own_iface else set()

    event_bus: Bus[Event] = Bus(max_queue_size=8192, overflow_policy="drop_oldest")
    alert_bus: Bus[Alert] = Bus(max_queue_size=2048, overflow_policy="drop_oldest")
    # recover_corrupt=True: agent nền phải sống sót qua một DB hỏng (mục B3).
    # File hỏng được dời sang một bên làm bằng chứng, không bao giờ bị xoá.
    # Agent la tien trinh DUY NHAT duoc doi schema. Xem Store.__init__.
    store = Store(recover_corrupt=True, allow_migration=True)
    ledger_ok, bad_record, ledger_message = store.verify_forensic_ledger()
    if not ledger_ok:
        logger.critical("FORENSIC LEDGER INVALID at record %s: %s", bad_record, ledger_message)
    else:
        logger.info("Forensic ledger: %s", ledger_message)
    checkpoint_path = Path(os.environ.get("SHIELD_FORENSIC_CHECKPOINT", str(store.path) + ".checkpoint.json"))
    if checkpoint_path.exists():
        checkpoint_ok, checkpoint_message = store.verify_forensic_checkpoint(checkpoint_path)
        if not checkpoint_ok:
            logger.critical("FORENSIC CHECKPOINT INVALID: %s", checkpoint_message)
    traffic_manager = TrafficManager(None, interface=own_iface)  # ipc gán ngay dưới
    tarpit_manager = tarpit.TarpitManager()
    helper_socket = os.environ.get("SHIELD_HELPER_SOCK")
    privileged_client = PrivilegedClient(Path(helper_socket)) if helper_socket else None
    # Dead-man switch (mục B8): cách ly một máy rồi mất khả năng gỡ là hỏng
    # nặng hơn thứ đang phòng chống. Không có công tắc này thì cách ly bị từ
    # chối thẳng.
    dead_man = DeadManSwitch(
        Path(os.environ.get("SHIELD_STATE_DIR", "/var/lib/shield")) / "isolation-deadman.json"
    )
    response_executor = ResponseExecutor(
        Quarantine(default_quarantine_root()), privileged_client=privileged_client,
        dead_man=dead_man,
        # Thất bại kiểm chứng phải đi vào pipeline detection, không chỉ vào giá
        # trị trả về. Giá trị trả về đi vào một hộp thoại rồi biến mất.
        event_sink=lambda event: event_bus.publish_nowait(event),
    )
    # Kill switch AI đọc lại từ đĩa: một công tắc an toàn quên mất mình đang
    # bật sau khi khởi động lại là một công tắc không dùng được. Biến môi
    # trường thắng giá trị đã lưu — người vận hành đặt nó trong unit file thì
    # đó là ý định rõ ràng nhất.
    if not os.environ.get("SHIELD_AI_KILL_SWITCH"):
        from shield.ai.capability import KILL_SWITCH_ENV

        if store.get_baseline("ai_kill_switch") == "1":
            os.environ[KILL_SWITCH_ENV] = "1"
            logger.warning("Kill switch AI đang BẬT (khôi phục từ lần chạy trước)")

    if not os.environ.get("SHIELD_RESPONSE_KILL_SWITCH"):
        from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

        if store.get_baseline("response_kill_switch") == "1":
            os.environ[RESPONSE_KILL_SWITCH_ENV] = "1"
            logger.warning("Công tắc dừng phản ứng đang BẬT (khôi phục từ lần chạy trước)")

    telemetry = KernelTelemetrySelector().detect()
    store.set_collector_health("kernel_telemetry", telemetry.backend, telemetry.available, telemetry.reason)
    config_manifest = os.environ.get("SHIELD_CONFIG_MANIFEST")
    if config_manifest:
        config_key = os.environ.get("SHIELD_CONFIG_PUBLIC_KEY")
        config_signature = os.environ.get("SHIELD_CONFIG_SIGNATURE")
        if not config_key or not config_signature:
            raise RuntimeError("signed configuration requires public key and signature")
        artifact_root = Path(os.environ.get("SHIELD_CONFIG_ARTIFACT_ROOT", "/opt/shield"))
        config_ok, config_errors = verify_update_manifest(
            Path(config_manifest), artifact_root, Path(config_key), Path(config_signature),
        )
        store.set_collector_health("signed_configuration", "openssl", config_ok,
                                   "verified" if config_ok else "; ".join(config_errors[:3]))
        if not config_ok:
            raise RuntimeError(f"signed configuration verification failed: {config_errors}")
    else:
        store.set_collector_health("signed_configuration", "development", False, "signature enforcement not configured")
    plugin_key = os.environ.get("SHIELD_PLUGIN_PUBLIC_KEY")
    store.set_collector_health("plugin_signatures", "openssl", bool(plugin_key),
                               "signature key configured" if plugin_key else "plugins remain disabled unless explicitly trusted")
    # Toàn bộ cơ chế chữ ký/HMAC là opt-in: không đặt key thì agent vẫn chạy,
    # chỉ là fail-open. Nói thẳng ra log lúc khởi động thay vì chôn trong tab
    # health — operator production cần biết mình đang chạy thiếu cái gì.
    unprotected = [
        name for name, configured in (
            ("rule pack signing (SHIELD_RULE_PUBLIC_KEY)", bool(os.environ.get("SHIELD_RULE_PUBLIC_KEY"))),
            ("config/update manifest (SHIELD_CONFIG_MANIFEST)", bool(os.environ.get("SHIELD_CONFIG_MANIFEST"))),
            ("plugin signing (SHIELD_PLUGIN_PUBLIC_KEY)", bool(plugin_key)),
            ("audit ledger HMAC (SHIELD_AUDIT_HMAC_KEY)", bool(os.environ.get("SHIELD_AUDIT_HMAC_KEY"))),
        ) if not configured
    ]
    if unprotected:
        logger.warning(
            "Chạy fail-open, chưa bật: %s. Sinh key bằng scripts/generate-signing-keys.sh "
            "rồi khai trong unit file trước khi dùng production (xem docs/OPERATIONS.md).",
            "; ".join(unprotected),
        )
    health_status = {
        "components": {
            "agent": True,
            "privileged_helper": bool(helper_socket and Path(helper_socket).exists()),
            "endpoint": bool(args.endpoint),
            "file_integrity": bool(args.fim_path),
            "network_discovery": bool(args.discover),
            "mitm": bool(args.mitm),
            "portscan": bool(args.portscan),
            "dns": True,
            "audit_journal": bool(args.journal),
            "kernel_telemetry": telemetry.available,
            "tamper_protection": True,
        },
        "telemetry": telemetry.to_dict(),
        "audit_only": True,
        "offline_analysis": True,
    }
    # --- Đường vào log từ máy khác (kế hoạch 1.1 phần A) ---------------
    #
    # Hai cửa, hai mức tin cậy khác nhau, không bao giờ trộn lẫn:
    #   log_ingest  — Shield Probe có mTLS, trust=authenticated
    #   syslog      — router/camera không xác thực được, trust=unauthenticated
    # Cả hai đều TẮT mặc định: phải cấu hình mới mở.
    ingest_server = None
    ingest_cert, ingest_key, ingest_ca = (
        os.environ.get("SHIELD_LOG_INGEST_CERT"), os.environ.get("SHIELD_LOG_INGEST_KEY"),
        os.environ.get("SHIELD_LOG_INGEST_CLIENT_CA"),
    )
    if any((ingest_cert, ingest_key, ingest_ca)):
        if not all((ingest_cert, ingest_key, ingest_ca)):
            raise RuntimeError(
                "log ingest cần đủ certificate, private key và client CA — "
                "chạy scripts/generate-probe-ca.sh init <host>"
            )
        ingest_listen = os.environ.get("SHIELD_LOG_INGEST_LISTEN", "0.0.0.0:9443")
        ingest_host, separator, ingest_port = ingest_listen.rpartition(":")
        if not separator or not ingest_host:
            raise RuntimeError("SHIELD_LOG_INGEST_LISTEN không hợp lệ (cần dạng host:port)")
        ingest_server = LogIngestServer(
            event_bus, FleetRegistry(store), store,
            fleet_server_context(ingest_cert, ingest_key, ingest_ca),
            ingest_host, int(ingest_port),
            int(os.environ.get("SHIELD_LOG_INGEST_RATE", DEFAULT_RATE_PER_PROBE)),
        )
        await ingest_server.start()
        store.set_collector_health("log_ingest", "mTLS TLSv1.3", True, f"listening on {ingest_listen}")
    else:
        store.set_collector_health("log_ingest", "disabled", True, "chưa cấu hình probe")

    syslog_collector = SyslogCollector(event_bus, store=store)

    # Công tắc giám sát (switch.py). Tạo trước IPC vì handle_command cần nó,
    # và đăng ký làm instance dùng chung để collector ở module khác
    # (collectors/discovery.py) hỏi được mà không phải luồn tham số.
    monitoring = set_switch(MonitoringSwitch(store))
    # `live` phải tồn tại TRƯỚC IpcServer: lambda on_command tham chiếu tới nó.
    # Đặt sau sẽ chạy đúng trong hầu hết trường hợp và đổ đúng lúc lệnh đầu
    # tiên tới sớm hơn dự kiến — dạng lỗi đã xảy ra một lần với đúng biến này.
    live = LiveStats()
    # Hộp chứa một tham chiếu thay đổi được: người dùng đổi cấu hình lúc đang
    # chạy thì `handle_command` phải thay được exporter, mà vòng lặp ghi lại
    # đang giữ tham chiếu cũ. Một dict một khoá là cách đơn giản nhất để cả hai
    # cùng nhìn vào một chỗ.
    exporter_box = {"exporter": LogExporter(
        ExportConfig.from_dict(store.get_log_export_config())
    )}
    ipc = IpcServer(
        on_command=lambda msg: handle_command(
            msg, store, own_iface, traffic_manager, event_bus, ipc, tarpit_manager, response_executor,
            privileged_client, health_status, monitoring, syslog_collector, ingest_server,
            exporter_box, live,
        )
    )
    traffic_manager.ipc = ipc

    await ipc.start()
    logger.info("Shield agent khởi động. DB: %s | Socket: %s", store.path, ipc.sock_path)

    # Nạp TẤT CẢ rule pack trong thư mục (mục B4): default/ssh/endpoint/
    # syslog/probe. Tách theo lĩnh vực để sửa một mảng không phải đụng cả file.
    rule_dir = Path(__file__).parent.parent / "rules"
    rule_public_key = Path(os.environ["SHIELD_RULE_PUBLIC_KEY"]) if os.environ.get("SHIELD_RULE_PUBLIC_KEY") else None
    # Đối chiếu định dạng khoá baseline TRƯỚC khi detector chạy dòng event đầu
    # tiên. Chạy sau thì loại vừa đổi định dạng đã kịp bắn ra một loạt cảnh báo
    # trước khi bị nén.
    from shield.evidence.resolver import GRAPH_KEY_FORMATS

    # Định dạng khoá đồ thị: đối chiếu TRƯỚC khi collector phát event đầu tiên.
    # Chạy sau thì node cũ và node mới cùng tồn tại một lúc, và trong khoảng đó
    # đồ thị có hai câu trả lời cho cùng một câu hỏi.
    for record in store.reconcile_graph_key_formats(GRAPH_KEY_FORMATS):
        logger.warning(
            "Dựng lại đồ thị cho %s (định dạng khoá %d -> %d): xoá %d thực thể, "
            "%d cạnh. Event và bằng chứng không bị chạm; đồ thị dựng lại từ "
            "lượt quan sát tới.",
            record["entity_type"], record["old_format"], record["new_format"],
            record["entities_removed"], record["edges_removed"])

    relearned = store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    for record in relearned:
        logger.warning(
            "Baseline %s học lại %d ngày (định dạng khoá %d -> %d, xoá %d khoá): "
            "cảnh báo hành vi mới của loại này tạm nén cho tới khi biết lại "
            "cái gì là bình thường.",
            record["kind"], record["learning_days"], record["old_format"],
            record["new_format"], record["deleted_keys"])
    baseline_detector = LocalBaselineDetector(store)

    detectors = [
        UnknownDeviceDetector(store),
        MitmDetector(store),
        PortscanDetector(store),
        LocalLogDetector(store, own_interfaces=own_interfaces),
        DnsDetector(store),
        EndpointDetector(),
        RuleDetector.from_directory(rule_dir, rule_public_key),
        BehaviorChainDetector(),
        baseline_detector,
    ]
    fleet_server = None
    fleet_cert, fleet_key, fleet_ca = (
        os.environ.get("SHIELD_FLEET_SERVER_CERT"), os.environ.get("SHIELD_FLEET_SERVER_KEY"),
        os.environ.get("SHIELD_FLEET_CLIENT_CA"),
    )
    if any((fleet_cert, fleet_key, fleet_ca)):
        if not all((fleet_cert, fleet_key, fleet_ca)):
            raise RuntimeError("fleet mTLS requires server certificate, private key and client CA")
        listen = os.environ.get("SHIELD_FLEET_LISTEN", "127.0.0.1:9443")
        host, separator, port_raw = listen.rpartition(":")
        if not separator or not host:
            raise RuntimeError("invalid SHIELD_FLEET_LISTEN")

        async def fleet_handler(command: str, payload: dict, endpoint_record: dict) -> dict:
            if command == "request_health":
                return {**health_status, "collector_health": store.collector_health()}
            if command == "request_assessment":
                profile_path = Path(__file__).resolve().parent.parent / "assessment" / "default-profile.json"
                result = await AssessmentRunner([], event_bus=event_bus, store=store).run(AssessmentProfile.load(profile_path))
                data = result.to_dict()
                return {"result": data, "coverage": coverage(data)}
            # Distribution exists in the protocol/RBAC model but applying an
            # update requires a local signed-manifest staging workflow.
            return {"accepted": False, "reason": "signed update staging is not enabled on this endpoint"}

        fleet_server = FleetControlServer(
            FleetRegistry(store), fleet_server_context(fleet_cert, fleet_key, fleet_ca),
            fleet_handler, host, int(port_raw),
        )
        await fleet_server.start()
        store.set_collector_health("fleet_control", "mTLS TLSv1.3", True, f"listening on {listen}")
    else:
        store.set_collector_health("fleet_control", "standalone", True, "offline standalone mode")
    # Phải dựng TRƯỚC vòng tiêu thụ event vì vòng đó ghi số vào đây.
    alert_consumer_task = asyncio.create_task(
        run_alert_consumer(alert_bus, store, ipc, exporter_box)
    )
    evidence_feed = LiveEvidenceFeed()
    event_consumer_task = asyncio.create_task(
        run_event_consumer(event_bus, alert_bus, store, detectors, ipc, live,
                           exporter_box, evidence_feed)
    )
    evidence_feed_task = asyncio.create_task(live_evidence_loop(evidence_feed, ipc))

    if store.recovery:
        # Người dùng PHẢI biết mình vừa mất lịch sử. Một Shield âm thầm chạy
        # tiếp trên DB rỗng nhìn y hệt một Shield khoẻ mạnh.
        logger.critical(
            "Database hỏng — đã dời sang %s, cứu được %d dòng, mất %d",
            store.recovery["quarantined_path"], store.recovery["rows_recovered"],
            store.recovery["rows_lost"],
        )
        # Dựng qua problems.py để nội dung gửi ra ngoài luôn là tiếng Anh và
        # luôn kèm việc cần làm — một chỗ duy nhất quyết định câu chữ.
        for problem in detect_problems(recovery=store.recovery):
            await alert_bus.publish(problem_to_alert(problem))

    supervisor = CollectorSupervisor(store, alert_bus)
    tasks = [
        alert_consumer_task,
        event_consumer_task,
        # Nút "Tắt Shield" trong app đặt cờ này; task duy nhất việc là đánh
        # thức main_async để thoát sạch.
        asyncio.create_task(shutdown_watch_loop()),
        asyncio.create_task(watchdog_loop(store)),
        asyncio.create_task(isolation_deadman_loop(dead_man, store, alert_bus, privileged_client)),
        # Syslog: tự tắt nếu allowlist rỗng (fail closed), nên luôn tạo task
        # được — chi phí gần bằng 0 khi chưa cấu hình.
        asyncio.create_task(supervisor.run("syslog_server", "rfc3164+rfc5424", syslog_collector.run)),
        # Lịch quét sâu — luôn chạy (chi phí gần như 0 nếu chưa bật ở Cài đặt,
        # chỉ đọc 1 dòng baseline mỗi 60s), không cần cờ CLI riêng.
        asyncio.create_task(scan_schedule_loop(store, event_bus, ipc, own_iface)),
        # Lưu lượng theo thiết bị đọc từ router — cũng gần như 0 chi phí nếu
        # chưa cấu hình backend ở Cài đặt (xem router_traffic_loop).
        asyncio.create_task(router_traffic_loop(store, ipc, own_iface)),
        # Theo dõi DNS của chính máy này — chỉ đọc cấu hình mỗi 5 phút, chi
        # phí không đáng kể, nên luôn bật (không cần cờ CLI riêng).
        asyncio.create_task(dns_monitor_loop(store, event_bus, ipc)),
        # Né tránh khẩn cấp — luôn chạy nền, không làm gì cho tới khi người
        # dùng tự bật ở Cài đặt (xem evasion_loop).
        asyncio.create_task(evasion_loop(store, ipc, own_iface)),
        # Tarpit phòng thủ — cũng không mở cổng nào cho tới khi tự bật.
        asyncio.create_task(tarpit_loop(store, ipc, alert_bus, tarpit_manager)),
        asyncio.create_task(maintenance_loop(store, alert_bus)),
        asyncio.create_task(tamper_monitor_loop(alert_bus, store)),
        asyncio.create_task(problem_watch_loop(store, alert_bus, ipc, syslog_collector, live)),
        asyncio.create_task(live_stats_loop(live, ipc)),
        asyncio.create_task(log_export_status_loop(ipc, exporter_box, live)),
        asyncio.create_task(runtime_health_loop(
            store, event_bus, alert_bus, ipc, privileged_client, baseline_detector,
            evidence_feed)),
    ]
    if fleet_server is not None:
        tasks.append(asyncio.create_task(fleet_server.server.serve_forever()))
    if args.inject_fake_events:
        tasks.append(asyncio.create_task(run_fake_injector(alert_bus)))
    if args.discover:
        tasks.append(asyncio.create_task(supervisor.run(
            "network_discovery", "arp-scan+nmap",
            lambda: discovery_loop(event_bus, interface=own_iface),
        )))
    # MỘT đường nhận cho cả ba nguồn quan sát gói tin.
    #
    # Trước đây mỗi cờ bật một vòng sniff scapy TRONG tiến trình này. Việc bóc
    # gói giờ nằm ở `shield-packet-collector`, một chương trình riêng và một gói
    # cài riêng — lõi chỉ nghe trên một socket. Helper vắng mặt là chuyện BÌNH
    # THƯỜNG: vòng nhận chờ nó xuất hiện, và mọi thứ khác của agent chạy như cũ.
    if args.mitm or args.portscan or args.dns:
        packet_health = packet_ingest.PacketIngestHealth()
        tasks.append(asyncio.create_task(supervisor.run(
            "packet_ingest", "helper",
            lambda: packet_ingest.ingest_loop(event_bus, health=packet_health,
                                              store=store),
        )))
    if args.mitm:
        tasks.append(asyncio.create_task(gateway_baseline_wizard_loop(store, ipc)))
    if args.portscan:
        tasks.append(asyncio.create_task(supervisor.run(
            "port_flow_aggregate", "aggregate",
            lambda: conn_watch.aggregate_loop(event_bus, store=store),
        )))
    if args.journal:
        tasks.append(asyncio.create_task(supervisor.run(
            "journal", "journalctl",
            lambda: journal.journal_loop(event_bus),
        )))
    if args.endpoint:
        tasks.append(asyncio.create_task(supervisor.run(
            "endpoint", "procfs+systemd+sysfs",
            lambda: endpoint.endpoint_loop(event_bus, args.endpoint_interval),
        )))
        if telemetry.backend == "ebpf":
            tasks.append(asyncio.create_task(supervisor.run(
                "kernel_telemetry", "ebpf",
                lambda: kernel.ebpf_exec_loop(event_bus, store),
            )))
    if args.fim_path:
        fim_paths = [Path(value).expanduser().resolve() for value in args.fim_path]
        tasks.append(asyncio.create_task(supervisor.run(
            "file_monitor", "selective-hash",
            lambda: endpoint.fim_loop(event_bus, fim_paths, args.fim_interval, store),
        )))

    # Vòng làm giàu báo cáo bằng văn xuôi model. Một task, có CHỦ SỞ HỮU rõ
    # ràng (huỷ ở `finally` bên dưới), tối đa một job cùng lúc, hàng đợi nằm
    # trong bảng chứ không trong bộ nhớ — nên một lần khởi động lại không làm
    # mất việc và cũng không để lại việc ma.
    #
    # KHÔNG phải một khung tác vụ nền tổng quát: nó chạy đúng một loại việc.
    enrichment_runner = None
    try:
        from shield.ai.enrichment import EnrichmentStore
        from shield.ai.enrichment_runner import SharedAiRunner

        from shield.ai.chat import ChatStore
        from shield.ai.enrichment_runner import Queue

        enrichment_jobs = EnrichmentStore(store.conn)
        chat_jobs = ChatStore(store.conn)
        reconciled = await asyncio.to_thread(enrichment_jobs.reconcile_startup)
        if any(reconciled.values()):
            logger.info("Job làm giàu sau khởi động lại: %s", reconciled)
        chat_reconciled = await asyncio.to_thread(chat_jobs.reconcile_startup)
        if any(chat_reconciled.values()):
            logger.info("Hỏi đáp sau khởi động lại: %s", chat_reconciled)
        # MỘT runner cho MỌI việc cần model. Hai runner độc lập nghĩa là hai
        # worker cùng chạy — 5 GiB và 600% CPU trên một máy mà agent bị giới
        # hạn 1 GiB — vì mỗi kho chỉ đếm được hàng của chính nó.
        enrichment_runner = SharedAiRunner(
            Queue("enrichment", enrichment_jobs,
                  lambda job: execute_enrichment_job(store, job)),
            Queue("chat", chat_jobs, lambda job: execute_chat_job(store, job)))
        enrichment_runner.start()
    except Exception as exc:  # noqa: BLE001 — làm giàu không được chặn agent
        logger.warning("Không khởi động được vòng làm giàu: %s", exc)

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    except _ShutdownRequested:
        logger.warning("Đang tắt Shield theo yêu cầu từ app — dừng toàn bộ collector")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if enrichment_runner is not None:
            # Huỷ AN TOÀN: job đang chạy quay về `pending`, không để lại
            # `running` mồ côi chặn hàng đợi tới lần khởi động sau.
            await enrichment_runner.stop()
        await traffic_manager.stop_all()
        await tarpit_manager.stop_all()
        if ingest_server is not None:
            await ingest_server.stop()
        await syslog_collector.stop()
        await ipc.close()
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="shield-agent")
    parser.add_argument(
        "--inject-fake-events",
        action="store_true",
        help="Sinh 10 alert giả để verify đường ống (giai đoạn 0)",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Bật collector arp-scan/nmap phát hiện thiết bị (giai đoạn 1, cần root)",
    )
    parser.add_argument(
        "--mitm",
        action="store_true",
        help="Bật arp_sniffer + 4 detector chống MITM (giai đoạn 2, cần root, cần scapy)",
    )
    parser.add_argument(
        "--portscan",
        action="store_true",
        help="Bật conn_watch + rule SCAN_PORTSCAN (giai đoạn 3, cần root, cần scapy)",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Bật dns_watch (bắt DNS đi tới server lạ, cần root + scapy). Việc "
        "theo dõi resolver/hosts luôn chạy sẵn, không cần cờ này.",
    )
    parser.add_argument(
        "--journal",
        action="store_true",
        help="Bật journalctl -f + 4 rule log máy (giai đoạn 4, không cần root nếu user trong group systemd-journal)",
    )
    parser.add_argument(
        "--endpoint", action="store_true",
        help="Theo dõi process và USB qua /proc, /sys (không tự động phản ứng)",
    )
    parser.add_argument(
        "--endpoint-interval", type=float, default=5.0, metavar="SECONDS",
        help="Chu kỳ endpoint snapshot, tối thiểu 1 giây (mặc định: 5)",
    )
    parser.add_argument(
        "--fim-path", action="append", default=[], metavar="PATH",
        help="File/thư mục cần giám sát toàn vẹn; có thể lặp lại nhiều lần",
    )
    parser.add_argument(
        "--fim-interval", type=float, default=30.0, metavar="SECONDS",
        help="Chu kỳ FIM, tối thiểu 5 giây (mặc định: 30)",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Interface mạng dùng cho arp-scan/nmap/sniff (mặc định: tự dò default route)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
