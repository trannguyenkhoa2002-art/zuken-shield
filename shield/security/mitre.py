"""MITRE ATT&CK metadata, suppression and bounded behavioral chains."""

from __future__ import annotations

import fnmatch
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from dataclasses import replace

from shield.common.models import Alert, Event, now
from shield.security.rules import EventRule


MITRE_BY_RULE: dict[str, tuple[str, str]] = {
    "ENDPOINT_SUSPICIOUS_EXEC_PATH": ("T1204", "Execution"),
    "ENDPOINT_DELETED_EXECUTABLE": ("T1070.004", "Defense Evasion"),
    "ENDPOINT_SECURITY_CONFIG_CHANGED": ("T1562.001", "Defense Evasion"),
    "ENDPOINT_SENSITIVE_LISTENER_OPENED": ("T1049", "Discovery"),
    "FILE_INTEGRITY_CHANGED": ("T1565.001", "Impact"),
    "LOCAL_SSH_BRUTEFORCE": ("T1110.001", "Credential Access"),
    "LOCAL_SUDO_FAIL": ("T1548", "Privilege Escalation"),
    "LOCAL_PROMISC_MODE": ("T1040", "Credential Access"),
    "SCAN_PORTSCAN": ("T1046", "Discovery"),
    "MITM_ARP_CONFLICT": ("T1557", "Credential Access"),
    "MITM_GATEWAY_MAC_CHANGED": ("T1557.002", "Credential Access"),
    "BEHAVIOR_EXEC_WRITE_CONNECT": ("T1059", "Execution"),
    "ANOMALY_NEW_BEHAVIOR": ("T1036", "Defense Evasion"),
}


def enrich_alert(alert: Alert) -> Alert:
    technique, tactic = MITRE_BY_RULE.get(alert.rule_id, ("", ""))
    if not technique:
        return alert
    evidence = dict(alert.evidence)
    evidence.setdefault("mitre_technique", technique)
    evidence.setdefault("mitre_tactic", tactic)
    return replace(alert, evidence=evidence)


def attack_coverage(alerts: list[dict]) -> dict:
    observed_rules = {str(item.get("rule_id", "")) for item in alerts}
    techniques = sorted({MITRE_BY_RULE[rule][0] for rule in observed_rules if rule in MITRE_BY_RULE})
    tactics = sorted({MITRE_BY_RULE[rule][1] for rule in observed_rules if rule in MITRE_BY_RULE})
    total = len({value[0] for value in MITRE_BY_RULE.values()})
    return {"techniques_observed": techniques, "tactics_observed": tactics,
            "techniques_catalogued": total,
            "coverage_percent": round(100 * len(techniques) / total, 1) if total else 100.0}


@dataclass(frozen=True)
class Suppression:
    rule_pattern: str
    subject_pattern: str = "*"
    expires_ts: float = 0.0
    reason: str = ""

    def matches(self, alert: Alert, at: float | None = None) -> bool:
        at = time.time() if at is None else at
        return (not self.expires_ts or at < self.expires_ts) and fnmatch.fnmatch(alert.rule_id, self.rule_pattern) and fnmatch.fnmatch(alert.subject, self.subject_pattern)


class SuppressionPolicy:
    def __init__(self, entries: list[Suppression] | None = None) -> None:
        self.entries = tuple(entries or ())

    def reason(self, alert: Alert) -> str | None:
        match = next((entry for entry in self.entries if entry.matches(alert)), None)
        return match.reason or "matched suppression" if match else None


# Nơi một dropper đặt payload: thư mục ai cũng ghi được, không nằm dưới quyền
# quản lý của trình quản lý gói. Danh sách cố ý NGẮN và tường minh.
#
# Vì sao cần lọc theo đường ghi: chuỗi `exec -> ghi file -> mở kết nối` mô tả
# đúng hành vi của một dropper, NHƯNG cũng mô tả đúng `apt` tải một gói, trình
# duyệt lưu file tải về, và mọi trình build. Trước 2.0 điều này không lộ ra vì
# collector chưa bao giờ phát `file_write` — chuỗi là code chết. Ngay khi
# telemetry chảy thật (mục 0.4), luật rộng như cũ sẽ kêu mỗi lần cập nhật gói.
#
# Corpus ground-truth bắt được đúng chuyện này ở mẫu
# `normal.package-manager-writes-then-fetches`.
DROPPER_PATH_PREFIXES = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/root/",
)

# Ghi vào đây là chuyện thường ngày của trình quản lý gói và dịch vụ hệ thống.
# Kiểm TRƯỚC danh sách trên, vì một số đường nằm trong cả hai.
MANAGED_PATH_PREFIXES = (
    "/var/cache/", "/var/lib/", "/var/log/", "/usr/", "/etc/", "/opt/",
    "/snap/", "/boot/",
)


def looks_like_a_dropped_payload(path: str) -> bool:
    """File này có nằm ở chỗ một dropper hay đặt payload không.

    Không phải phép thử hoàn hảo — trình duyệt cũng ghi vào /tmp. Nó chỉ loại
    bỏ nhóm dương tính giả LỚN NHẤT và dễ nhận nhất, và phần còn lại là việc
    của hiệu chuẩn: `detector_calibration` sẽ nói detector này đúng bao nhiêu
    phần trăm trên máy CỦA BẠN, thay vì để một con số đoán mò quyết định thay.
    """
    text = str(path or "")
    if not text.startswith("/"):
        return False
    if text.startswith(MANAGED_PATH_PREFIXES):
        return False
    return text.startswith(DROPPER_PATH_PREFIXES)


class BehaviorChainDetector:
    """Detect exec → write → connect for one process identity in 120 seconds."""

    ORDER = ("process_exec", "file_write", "socket_connect")

    def __init__(self, window_s: float = 120.0, max_identities: int = 4096) -> None:
        self.window_s = window_s
        self.max_identities = max_identities
        self._history: dict[str, deque[tuple[float, str, dict]]] = defaultdict(lambda: deque(maxlen=12))
        self._last_emitted: dict[str, float] = {}

    def handle_event(self, event: Event) -> list[Alert]:
        if event.kind not in self.ORDER:
            return []
        identity = str(event.data.get("process_identity") or f"{event.data.get('pid', '?')}:{event.data.get('start_ticks', '?')}")
        if identity == "?:?":
            return []
        if identity not in self._history and len(self._history) >= self.max_identities:
            oldest = min(self._history, key=lambda key: self._history[key][-1][0])
            self._history.pop(oldest, None)
        history = self._history[identity]
        history.append((event.ts, event.kind, dict(event.data)))
        cutoff = event.ts - self.window_s
        while history and history[0][0] < cutoff:
            history.popleft()
        kinds = [item[1] for item in history]
        cursor = 0
        for kind in kinds:
            if kind == self.ORDER[cursor]:
                cursor += 1
                if cursor == len(self.ORDER):
                    break
        if cursor != len(self.ORDER) or (identity in self._last_emitted and event.ts - self._last_emitted[identity] < self.window_s):
            return []

        # Mắt xích "ghi file" phải là ghi vào chỗ đáng ngờ. Không có điều kiện
        # này thì mỗi lượt `apt upgrade` là một alert mức nguy cấp.
        written = [item[2].get("path", "") for item in history if item[1] == "file_write"]
        dropped = [path for path in written if looks_like_a_dropped_payload(path)]
        if not dropped:
            return []
        self._last_emitted[identity] = event.ts
        return [Alert(
            # `warning`, không phải `critical`. Chuỗi này chỉ ra một thứ ĐÁNG
            # XEM, không phải một thứ chắc chắn xấu — và một detector chưa hiệu
            # chuẩn mà kêu mức nguy cấp sẽ dạy người dùng bỏ qua mức nguy cấp.
            now(), "BEHAVIOR_EXEC_WRITE_CONNECT", "warning",
            "Suspicious execution chain",
            "A process executed, wrote a file into a location droppers use, "
            "then opened a connection",
            identity,
            evidence={"process_identity": identity, "sequence": kinds,
                      "dropped_paths": dropped[:5], **event.data},
            playbook=["snapshot_state"],
        )]


def import_sigma_subset(document: dict) -> EventRule:
    """Import a deliberately small deterministic Sigma-like subset.

    Supported documents use logsource.category, one selection with one equality
    field, and condition exactly `selection`. YAML parsing stays with callers.
    """
    detection = document.get("detection") or {}
    selection = detection.get("selection") or {}
    if detection.get("condition") != "selection" or not isinstance(selection, dict) or len(selection) != 1:
        raise ValueError("only one equality selection is supported")
    field, value = next(iter(selection.items()))
    level = str(document.get("level", "medium"))
    severity = {"low": "info", "medium": "warning", "high": "warning", "critical": "critical"}.get(level)
    if severity is None:
        raise ValueError("unsupported Sigma level")
    return EventRule(
        id=str(document.get("id") or document.get("title", "SIGMA_RULE")).upper().replace(" ", "_"),
        version=1, source=None, kind=str((document.get("logsource") or {}).get("category", "")),
        field=str(field), operator="eq", value=value, severity=severity,
        title=str(document.get("title", "Imported Sigma rule")),
        detail=f"Sigma selection matched: {field}={value}", subject_field=str(field),
        playbook=("snapshot_state",),
    )
