"""Vùng xám: đáng nghi nhưng chưa đủ bằng chứng — Shield KHÔNG được giấu.

Trước đây ba loại tín hiệu biến mất im lặng:

- **below_threshold** — detector thấy 3 lần SSH sai (ngưỡng là 5) hay dò
  8 cổng (ngưỡng 15) và trả về rỗng. Người phân tích không bao giờ biết đã
  có một lượt thử "gần đủ".
- **low_confidence** — alert có Behavior Risk cao nhưng Evidence Confidence
  thấp (security/evidence_model): nguy hiểm NẾU đúng, nhưng chưa đủ bằng
  chứng. Alert vẫn tồn tại như trước; vùng xám nói thêm "đang chờ bằng chứng
  gì".
- **suppressed** — alert bị policy tắt tiếng. Tắt tiếng là quyết định của
  người vận hành, không phải lý do để dấu vết biến mất khỏi mắt người điều tra.

Chỉ CON NGƯỜI quyết định một mục vùng xám: nâng lên incident hoặc bỏ qua kèm
ghi chú. Không có đường nào để model, correlation hay scoring tự nâng —
`decide()` đòi `principal` từ IPC (uid/pid của phiên giao diện) và ghi audit.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass

from shield.common.models import Alert

GRAY_SCHEMA = """
CREATE TABLE IF NOT EXISTS gray_zone (
    entry_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                 -- below_threshold | low_confidence | suppressed
    rule_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    title TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    evidence_confidence INTEGER NOT NULL DEFAULT -1,
    missing TEXT NOT NULL DEFAULT '[]',
    evidence TEXT NOT NULL DEFAULT '{}',
    alert_id INTEGER NOT NULL DEFAULT 0,
    count INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'open', -- open | promoted | dismissed
    decided_by TEXT NOT NULL DEFAULT '',
    decided_ts REAL NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    incident_id TEXT NOT NULL DEFAULT ''
);
"""
GRAY_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_gray_zone_open ON gray_zone(state, kind, rule_id, subject);
CREATE INDEX IF NOT EXISTS idx_gray_zone_seen ON gray_zone(last_seen);
"""

KINDS = ("below_threshold", "low_confidence", "suppressed")
DECISIONS = ("promote", "dismiss")
MAX_NOTE_CHARS = 1000


@dataclass(frozen=True)
class GrayThresholds:
    """Ngưỡng của vùng xám. Đọc từ unit file (môi trường), có mặc định.

    Không nhận từ IPC: đổi ngưỡng là đổi cái người phân tích được thấy, và
    việc đó thuộc cấu hình được quản lý như mọi cấu hình khác của agent.
    """

    min_risk: int = 40
    confirm_min_confidence: int = 70

    @staticmethod
    def from_env(env=os.environ) -> "GrayThresholds":
        def clamp(name: str, default: int) -> int:
            try:
                return max(0, min(100, int(env.get(name, default))))
            except (TypeError, ValueError):
                return default
        return GrayThresholds(clamp("SHIELD_GRAY_MIN_RISK", 40),
                              clamp("SHIELD_CONFIRM_MIN_CONFIDENCE", 70))


def classify(alert: Alert, *, suppressed_reason: str | None,
             thresholds: GrayThresholds) -> tuple[str, str] | None:
    """(kind, reason) nếu alert thuộc vùng xám, None nếu không. Hàm thuần."""
    near_miss = (alert.evidence or {}).get("gray_zone")
    if isinstance(near_miss, dict):
        return "below_threshold", str(near_miss.get("reason") or "below detection threshold")
    if suppressed_reason:
        return "suppressed", f"suppressed by policy: {suppressed_reason}"
    basis = str((alert.evidence_assessment or {}).get("basis", "generic"))
    if (basis.startswith("model:") and alert.risk_score >= thresholds.min_risk
            and 0 <= alert.evidence_confidence < thresholds.confirm_min_confidence):
        return "low_confidence", (
            f"risk {alert.risk_score}/100 but evidence confidence "
            f"{alert.evidence_confidence}/100 < {thresholds.confirm_min_confidence}")
    return None


def is_candidate_only(alert: Alert) -> bool:
    """Near-miss của detector: chỉ vào vùng xám, KHÔNG thành alert/incident/thông báo."""
    return isinstance((alert.evidence or {}).get("gray_zone"), dict)


class GrayZoneStore:
    def __init__(self, conn, clock=time.time) -> None:
        self.conn = conn
        self._clock = clock

    def record(self, alert: Alert, kind: str, reason: str) -> dict:
        """Ghi hoặc gộp: cùng (kind, rule, subject) đang mở là MỘT mục, tăng count."""
        if kind not in KINDS:
            raise ValueError(f"unknown gray-zone kind {kind!r}")
        ts = float(alert.ts or self._clock())
        missing = list((alert.evidence_assessment or {}).get("missing") or [])
        evidence = {k: v for k, v in (alert.evidence or {}).items() if k != "gray_zone"}
        row = self.conn.execute(
            "SELECT entry_id, count FROM gray_zone WHERE state='open' AND kind=? AND rule_id=? "
            "AND subject=?", (kind, alert.rule_id, alert.subject)).fetchone()
        with self.conn:
            if row:
                entry_id, count = row
                self.conn.execute(
                    "UPDATE gray_zone SET count=?, last_seen=?, reason=?, risk_score=?, "
                    "evidence_confidence=?, missing=?, evidence=?, alert_id=CASE WHEN ?>0 THEN ? "
                    "ELSE alert_id END WHERE entry_id=?",
                    (count + 1, ts, reason, alert.risk_score, alert.evidence_confidence,
                     json.dumps(missing), json.dumps(evidence, default=str), alert.alert_id,
                     alert.alert_id, entry_id))
            else:
                entry_id = uuid.uuid4().hex
                self.conn.execute(
                    "INSERT INTO gray_zone (entry_id, kind, rule_id, subject, title, reason, risk_score, "
                    "evidence_confidence, missing, evidence, alert_id, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (entry_id, kind, alert.rule_id, alert.subject, alert.title, reason,
                     alert.risk_score, alert.evidence_confidence, json.dumps(missing),
                     json.dumps(evidence, default=str), alert.alert_id, ts, ts))
        return self.get(entry_id) or {}

    def get(self, entry_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT entry_id, kind, rule_id, subject, title, reason, risk_score, evidence_confidence, "
            "missing, evidence, alert_id, count, first_seen, last_seen, state, decided_by, decided_ts, "
            "note, incident_id FROM gray_zone WHERE entry_id=?", (str(entry_id),)).fetchone()
        return _row(row) if row else None

    def entries(self, state: str | None = "open", limit: int = 200) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        if state:
            rows = self.conn.execute(
                "SELECT entry_id FROM gray_zone WHERE state=? ORDER BY last_seen DESC LIMIT ?",
                (state, limit)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT entry_id FROM gray_zone ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [entry for (entry_id,) in rows if (entry := self.get(entry_id)) is not None]

    def decide(self, entry_id: str, decision: str, *, principal: str, note: str = "",
               incident_id: str = "") -> dict:
        """Quyết định của NGƯỜI. Chỉ mục đang mở mới quyết định được, một lần."""
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}")
        if not principal or not principal.startswith("uid="):
            raise ValueError("a gray-zone decision needs the analyst's IPC principal")
        entry = self.get(entry_id)
        if entry is None:
            raise ValueError("gray-zone entry not found")
        if entry["state"] != "open":
            raise ValueError(f"entry already {entry['state']}")
        state = "promoted" if decision == "promote" else "dismissed"
        with self.conn:
            self.conn.execute(
                "UPDATE gray_zone SET state=?, decided_by=?, decided_ts=?, note=?, incident_id=? "
                "WHERE entry_id=? AND state='open'",
                (state, principal, self._clock(), str(note)[:MAX_NOTE_CHARS], incident_id, entry_id))
        return self.get(entry_id) or {}

    def prune(self, older_than_ts: float, limit: int = 5000) -> int:
        """Xoá mục ĐÃ QUYẾT ĐỊNH quá hạn. Mục đang mở giữ lại — chưa ai xem nó."""
        with self.conn:
            return int(self.conn.execute(
                "DELETE FROM gray_zone WHERE entry_id IN (SELECT entry_id FROM gray_zone "
                "WHERE state!='open' AND last_seen < ? LIMIT ?)", (older_than_ts, int(limit))).rowcount or 0)


def _row(row) -> dict:
    keys = ("entry_id", "kind", "rule_id", "subject", "title", "reason", "risk_score",
            "evidence_confidence", "missing", "evidence", "alert_id", "count", "first_seen",
            "last_seen", "state", "decided_by", "decided_ts", "note", "incident_id")
    item = dict(zip(keys, row, strict=True))
    item["missing"] = json.loads(item["missing"] or "[]")
    item["evidence"] = json.loads(item["evidence"] or "{}")
    return item
