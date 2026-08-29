"""Thông báo bằng TIẾNG ANH khi bản thân Shield gặp vấn đề.

Khác với alert bảo mật (kẻ khác làm gì đó), đây là chuyện của chính Shield:
collector chết, log đang bị rớt, probe im lặng, database vừa phải phục hồi.
Trước đây những thứ này chỉ nằm trong tab Sức khoẻ và journald — nghĩa là chỉ
ai chủ động mở ra xem mới biết, đúng lúc đáng lẽ phải được báo.

Ba quyết định trong thiết kế:

1. **Tiếng Anh, không qua i18n.** Thông báo đi ra ngoài máy (Telegram, điện
   thoại), có thể tới tay người trực khác. Nội dung alert bảo mật vốn đã là
   tiếng Anh; giữ cùng một ngôn ngữ cho mọi thứ rời khỏi máy.
2. **Mỗi vấn đề phải kèm việc cần làm.** Một thông báo nói "có vấn đề" mà không
   nói làm gì tiếp thì lần thứ ba người ta sẽ tắt nó đi.
3. **Báo cả lúc hết vấn đề.** Thông báo chỉ biết kêu mà không bao giờ nói "đã
   ổn" dạy người dùng bỏ qua nó.

`detect_problems` là hàm thuần, nhận vào các bản chụp trạng thái dạng dict —
kiểm thử được mà không cần agent sống, giống cách guardian làm.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# Dùng chung định nghĩa với `overall_health`: hai danh sách cho cùng một khái
# niệm nghĩa là cái thứ hai sẽ lạc hậu.
from shield.security.health import NON_TELEMETRY_COMPONENTS

# Ngưỡng
PROBE_SILENT_S = 15 * 60          # probe im lặng bao lâu thì coi là mất
# Agent phải chạy đủ lâu rồi mới kết luận một nguồn là im lặng: ngay sau khi
# khởi động thì mọi thứ đều "chưa sinh event", và báo động lúc đó là báo giả
# hàng loạt — đúng thời điểm người dùng đang nhìn.
STARTUP_GRACE_S = 10 * 60
# Backend mang một trong các nhãn này nghĩa là tính năng CHƯA BẬT, không phải hỏng.
NOT_ENABLED_BACKENDS = frozenset({"disabled", "development", "not configured", "unavailable"})
SYSLOG_DROP_THRESHOLD = 100       # số gói nhân bỏ giữa hai lượt kiểm

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


@dataclass(frozen=True)
class Problem:
    problem_id: str          # định danh ổn định, dùng để so giữa hai lượt
    severity: str            # "warning" | "critical"
    title: str               # tiếng Anh, một dòng
    detail: str              # tiếng Anh, chuyện gì đã xảy ra
    remedy: str              # tiếng Anh, làm gì tiếp
    evidence: dict = field(default_factory=dict)

    def message(self) -> str:
        """Nội dung gửi ra notify-send / Telegram."""
        return f"{self.detail}\nWhat to do: {self.remedy}"


def component_is_enabled(row: dict) -> bool:
    """Component này có thật sự được bật không.

    `signed_configuration` và `plugin_signatures` báo `healthy=False` khi chưa
    cấu hình chữ ký — đó là tính năng tuỳ chọn chưa bật, không phải hỏng. Gộp
    hai thứ đó làm một sẽ đẻ ra báo động cho những thứ chưa bao giờ chạy.
    """
    backend = str(row.get("backend", "")).strip().lower()
    if backend in NOT_ENABLED_BACKENDS:
        return False
    detail = f"{row.get('detail', '')} {row.get('error_message', '')}".lower()
    return not any(mark in detail for mark in (
        "not configured", "chưa cấu hình", "disabled", "not available", "chưa bật",
    ))


def detect_problems(
    collector_health: list[dict] | None = None,
    probe_health: list[dict] | None = None,
    syslog_stats: dict | None = None,
    previous_syslog_drops: int = 0,
    recovery: dict | None = None,
    now_ts: float | None = None,
    idle_collectors: list[dict] | None = None,
    agent_uptime_s: float = 0.0,
) -> list[Problem]:
    """Mọi vấn đề đang diễn ra, dựng từ các bản chụp trạng thái."""
    at = time.time() if now_ts is None else now_ts
    problems: list[Problem] = []

    for row in collector_health or []:
        name = str(row.get("component", "unknown"))
        state = str(row.get("state", ""))
        detail = str(row.get("error_message") or row.get("detail") or "")
        if name in NON_TELEMETRY_COMPONENTS:
            # Thành phần không thu telemetry: nói đúng thứ đã hỏng, không nói
            # "mảng này của mạng bạn đang không được giám sát". Câu đó sai với
            # một worker model, và một cảnh báo sai là cách nhanh nhất khiến
            # người dùng học được rằng cảnh báo của Shield không đáng đọc.
            if state in {"failed", "degraded"}:
                problems.append(Problem(
                    problem_id=f"ai_degraded:{name}",
                    severity="warning",
                    title="AI analysis is degraded",
                    detail=("Shield's optional AI analysis is not running normally"
                            + (f" ({detail})" if detail else "")
                            + ". Detection, alerting and response are unaffected; "
                              "investigations fall back to the deterministic "
                              "local analyser."),
                    remedy=("No action is required for protection. To investigate, "
                            "see `journalctl -u shield-agent -n 50`."),
                    evidence={"component": name, "state": state, "detail": detail},
                ))
            continue
        if not component_is_enabled(row):
            # Tính năng tuỳ chọn chưa bật thì không thể "đã dừng". Báo động cho
            # thứ chưa bao giờ chạy là cách nhanh nhất khiến người dùng học được
            # rằng cảnh báo của Shield không đáng đọc.
            continue
        if state == "failed" or row.get("healthy") is False:
            problems.append(Problem(
                problem_id=f"collector_failed:{name}",
                severity="critical",
                title=f"Collector '{name}' has stopped",
                detail=(f"Shield is no longer receiving data from '{name}'"
                        + (f": {detail}" if detail else "")
                        + ". This part of your network is currently unmonitored."),
                remedy=("Check `journalctl -u shield-agent -n 50` for the cause, "
                        "then restart with `sudo systemctl restart shield-agent`."),
                evidence={"component": name, "state": state, "detail": detail},
            ))
            continue

    for row in probe_health or []:
        probe_id = str(row.get("probe_id", "unknown"))
        name = str(row.get("display_name") or probe_id)
        last_seen = float(row.get("last_seen") or row.get("last_event_ts") or 0.0)
        if last_seen and at - last_seen > PROBE_SILENT_S:
            problems.append(Problem(
                problem_id=f"probe_silent:{probe_id}",
                severity="critical",
                title=f"Probe '{name}' has stopped sending logs",
                detail=(f"No logs received from '{name}' for "
                        f"{int((at - last_seen) / 60)} minutes. Either that machine is off, "
                        f"the network path is broken, or someone stopped the probe."),
                remedy=("Check the machine directly rather than only its logs — a probe that "
                        "goes silent during an incident is itself a finding."),
                evidence={"probe_id": probe_id, "silent_s": at - last_seen},
            ))
        dropped = int(row.get("dropped") or 0)
        if dropped:
            problems.append(Problem(
                problem_id=f"probe_dropping:{probe_id}",
                severity="warning",
                title=f"Probe '{name}' is sending faster than Shield accepts",
                detail=(f"{dropped} log lines from '{name}' were refused by the rate limit. "
                        f"The probe keeps them queued and retries, but a permanent overload "
                        f"means its backlog will grow until the spool overflows."),
                remedy=("Narrow what that probe collects, or raise SHIELD_LOG_INGEST_RATE "
                        "if the volume is expected."),
                evidence={"probe_id": probe_id, "dropped": dropped},
            ))

    for row in (idle_collectors or []) if agent_uptime_s >= STARTUP_GRACE_S else []:
        source = str(row.get("source", "unknown"))
        idle_minutes = int(float(row.get("idle_s", 0.0)) / 60)
        problems.append(Problem(
            problem_id=f"source_idle:{source}",
            severity="warning",
            title=f"Collector '{source}' has produced nothing for {idle_minutes} minutes",
            detail=(f"'{source}' was working earlier today but has produced no events for "
                    f"{idle_minutes} minutes. A collector that is running but silent looks "
                    f"exactly like a quiet network, which is why this is worth saying out loud."),
            remedy=("If the network really is idle this is normal. If it is not, restart with "
                    "`sudo systemctl restart shield-agent` and watch the live event rate."),
            evidence={"source": source, "idle_s": row.get("idle_s", 0.0),
                      "events_total": row.get("total", 0)},
        ))

    stats = syslog_stats or {}
    drops = int(stats.get("kernel_dropped", 0) or 0)
    # -1 nghĩa là không đọc được bộ đếm, KHÔNG phải không mất gói nào.
    if drops > 0 and drops - previous_syslog_drops >= SYSLOG_DROP_THRESHOLD:
        lost = drops - previous_syslog_drops
        problems.append(Problem(
            problem_id="syslog_kernel_drops",
            severity="critical",
            title="Syslog messages are being dropped before Shield sees them",
            detail=(f"The kernel discarded {lost} syslog datagrams since the last check "
                    f"because they arrived faster than Shield could read them. "
                    f"Those log lines are gone and cannot be recovered."),
            remedy=("Reduce what the sending devices forward, or send high-volume sources "
                    "through a probe over TCP instead of raw syslog over UDP."),
            evidence={"dropped_total": drops, "dropped_since_last_check": lost},
        ))

    if recovery:
        problems.append(Problem(
            problem_id="database_recovered",
            severity="critical",
            title="Shield recovered its database after corruption",
            detail=(f"The database was corrupt and had to be rebuilt. "
                    f"{recovery.get('rows_recovered', 0)} rows were recovered and "
                    f"{recovery.get('rows_lost', 0)} were lost. "
                    f"The damaged file was kept as evidence at "
                    f"{recovery.get('quarantined_path', 'the quarantine path')}."),
            remedy=("Check the disk with `smartctl -a` — corruption is usually failing "
                    "hardware, but it can also be the trace of an attack. Some history "
                    "is missing from before this point."),
            evidence=dict(recovery),
        ))

    return problems


class ProblemReporter:
    """Nhớ vấn đề nào đã báo, để chỉ báo khi có THAY ĐỔI.

    Gửi lại cùng một thông báo mỗi 30 giây là cách nhanh nhất khiến người dùng
    tắt thông báo — và khi đó cái tiếp theo, cái thật sự quan trọng, cũng không
    tới được ai.
    """

    def __init__(self) -> None:
        self.active: dict[str, Problem] = {}

    def sync(self, problems: list[Problem]) -> tuple[list[Problem], list[Problem]]:
        """Trả về (vấn đề mới, vấn đề đã hết)."""
        current = {problem.problem_id: problem for problem in problems}
        opened = [problem for key, problem in current.items() if key not in self.active]
        resolved = [problem for key, problem in self.active.items() if key not in current]
        self.active = current
        return opened, resolved


def resolved_message(problem: Problem) -> str:
    """Thông báo khi một vấn đề đã hết. Xem quyết định 3 ở đầu file."""
    return f"Resolved: {problem.title}. Shield is receiving data from this source again."


def problem_to_alert(problem: Problem):
    """Đưa vấn đề vào đúng đường ống alert sẵn có.

    Không dựng kênh riêng: đi qua alert_bus thì vấn đề được lưu, hiện trong tab
    Cảnh báo, vào forensic ledger và chịu luật chặn trùng — miễn phí toàn bộ.
    `notify_always` cho phép mức `warning` cũng được gửi ra ngoài; alert bảo mật
    vẫn giữ nguyên quy tắc chỉ gửi `critical`, vì vấn đề đã được chặn trùng ở
    ProblemReporter nên không có nguy cơ dội thông báo.
    """
    from shield.common.models import Alert, now

    return Alert(
        now(), f"SHIELD_PROBLEM_{problem.problem_id.split(':')[0].upper()}",
        problem.severity, problem.title, problem.message(),
        problem.problem_id,
        evidence={"observed": True, "notify_always": True,
                  "remedy": problem.remedy, **problem.evidence},
        playbook=["snapshot_state"],
    )
