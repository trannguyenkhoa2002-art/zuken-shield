"""Live Investigation Workspace: nhiều tab log song song, mỗi tab một bộ lọc.

Mọi quyết định của workspace nằm ở đây, dưới dạng logic thuần có trần:

- `WorkspaceFilter` — kind / source / một thực thể (IP, MAC, user, process,
  PID, cổng) / chuỗi tìm. Khớp trên CẢ bản chuẩn hoá lẫn dòng gốc.
- `TabState` — Live / Pause / Replay / Search cho một tab; bộ đệm có trần,
  lúc Pause không mất event (giữ tới trần, đếm phần bị bỏ).
- `Workspace` — tối đa `MAX_TABS` tab, phân phối event live cho từng tab.
- `discover_groups` — nhóm KHÔNG viết cứng: kind/source và thực thể xuất hiện
  trong telemetry; cái mới thấy trong 24 giờ được đánh dấu `new`.

Workspace là màn hình THỦ CÔNG. Nó không tạo alert hay incident và không đổi
gì ở engine correlation: 20 lần SSH sai vẫn thành một incident ở engine, còn ở
đây người phân tích vẫn xem được từng event gốc.
"""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field

MAX_TABS = 10
MAX_ROWS = 2000          # dòng giữ trong một tab
MAX_PENDING = 5000       # event giữ lại trong lúc Pause
NEW_WINDOW_S = 86400.0   # "mới" = lần đầu thấy trong 24 giờ

# Trường dữ liệu chứa từng loại thực thể, theo tên collector đang dùng. Một bộ
# lọc thực thể khớp nếu BẤT KỲ trường nào mang đúng giá trị.
ENTITY_KEYS: dict[str, tuple[str, ...]] = {
    "ip": ("src_ip", "dst_ip", "remote_ip", "source_ip", "ip", "gateway_ip", "local_ip"),
    "mac": ("mac", "src_mac", "observed_mac", "baseline_mac"),
    "user": ("user", "username", "auid_name"),
    "process": ("exe", "comm", "process", "name"),
    "pid": ("pid", "ppid"),
    "port": ("remote_port", "dst_port", "port", "local_port"),
}
# Loại thực thể của evidence graph ứng với loại lọc của workspace.
GRAPH_TYPES = {"ip": "ip", "mac": "device", "user": "user"}

WORKSPACE_SCHEMA = """
CREATE TABLE IF NOT EXISTS workspace_kinds (
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (source, kind)
);
"""


@dataclass(frozen=True)
class WorkspaceFilter:
    kinds: frozenset[str] = frozenset()
    sources: frozenset[str] = frozenset()
    entity_type: str = ""
    entity_value: str = ""
    text: str = ""

    def __post_init__(self) -> None:
        if self.entity_type and self.entity_type not in ENTITY_KEYS:
            raise ValueError(f"unknown entity type {self.entity_type!r}")
        if bool(self.entity_type) != bool(self.entity_value):
            raise ValueError("entity filter needs both a type and a value")

    @staticmethod
    def from_dict(raw: dict) -> "WorkspaceFilter":
        return WorkspaceFilter(
            kinds=frozenset(str(k) for k in raw.get("kinds") or () if k),
            sources=frozenset(str(s) for s in raw.get("sources") or () if s),
            entity_type=str(raw.get("entity_type") or ""),
            entity_value=str(raw.get("entity_value") or "")[:256],
            text=str(raw.get("text") or "")[:256],
        )

    def to_dict(self) -> dict:
        return {"kinds": sorted(self.kinds), "sources": sorted(self.sources),
                "entity_type": self.entity_type, "entity_value": self.entity_value,
                "text": self.text}

    def label(self) -> str:
        parts = []
        if self.entity_type:
            parts.append(f"{self.entity_type}={self.entity_value}")
        if self.kinds:
            parts.append(",".join(sorted(self.kinds)))
        if self.sources:
            parts.append("@" + ",".join(sorted(self.sources)))
        if self.text:
            parts.append(f'"{self.text}"')
        return " ".join(parts) or "*"

    def matches(self, event: dict) -> bool:
        if self.kinds and event.get("kind") not in self.kinds:
            return False
        if self.sources and event.get("source") not in self.sources:
            return False
        data = event.get("data") or {}
        if self.entity_type:
            wanted = self.entity_value.lower()
            if not any(str(data.get(key, "")).lower() == wanted
                       for key in ENTITY_KEYS[self.entity_type] if key in data):
                return False
        if self.text:
            needle = self.text.lower()
            haystack = (str(event.get("raw") or "") + " " + json.dumps(data, default=str)).lower()
            if needle not in haystack:
                return False
        return True


@dataclass
class TabState:
    """Một tab. Mọi chế độ đều có trần; không chế độ nào làm mất dữ liệu im lặng."""

    filter: WorkspaceFilter
    mode: str = "live"                  # live | paused | replay
    rows: deque = field(default_factory=lambda: deque(maxlen=MAX_ROWS))
    pending: deque = field(default_factory=lambda: deque(maxlen=MAX_PENDING))
    evicted: int = 0                    # dòng bị đẩy khỏi bộ đệm tab
    dropped_while_paused: int = 0       # vượt MAX_PENDING lúc Pause
    matched: int = 0

    def offer(self, event: dict) -> bool:
        """Event live. True nếu nó khớp bộ lọc (dù đang hiện hay đang giữ)."""
        if not self.filter.matches(event):
            return False
        self.matched += 1
        if self.mode == "live":
            self._append(event)
        else:
            # Pause và Replay đều GIỮ event live lại, để quay về Live không
            # có lỗ hổng. Tràn thì đếm, không im lặng.
            if len(self.pending) == self.pending.maxlen:
                self.dropped_while_paused += 1
            self.pending.append(event)
        return True

    def pause(self) -> None:
        if self.mode == "live":
            self.mode = "paused"

    def resume(self) -> list[dict]:
        """Về Live: đổ phần đã giữ vào tab, trả về đúng những dòng vừa đổ."""
        flushed = list(self.pending)
        self.pending.clear()
        for event in flushed:
            self._append(event)
        self.mode = "live"
        return flushed

    def load_replay(self, events: list[dict]) -> None:
        """Lịch sử từ database, xếp theo thời gian TĂNG dần — đọc như nó đã xảy ra."""
        self.mode = "replay"
        self.rows.clear()
        for event in sorted((e for e in events if self.filter.matches(e)),
                            key=lambda e: (float(e.get("ts") or 0), str(e.get("event_id") or ""))):
            self._append(event)

    def search(self, text: str) -> list[dict]:
        """Tìm trong những gì tab đang giữ, cả dòng gốc lẫn bản chuẩn hoá."""
        probe = WorkspaceFilter(text=text)
        return [event for event in self.rows if probe.matches(event)]

    def _append(self, event: dict) -> None:
        if len(self.rows) == self.rows.maxlen:
            self.evicted += 1
        self.rows.append(event)


class Workspace:
    def __init__(self, max_tabs: int = MAX_TABS) -> None:
        self.max_tabs = max_tabs
        self.tabs: dict[str, TabState] = {}
        self._next = 0

    def open(self, flt: WorkspaceFilter) -> str:
        if len(self.tabs) >= self.max_tabs:
            raise ValueError(f"workspace already has {self.max_tabs} tabs")
        self._next += 1
        tab_id = f"tab-{self._next}"
        self.tabs[tab_id] = TabState(flt)
        return tab_id

    def close(self, tab_id: str) -> None:
        self.tabs.pop(tab_id, None)

    def route(self, event: dict) -> list[str]:
        """Phân phối một event live; trả về các tab nó khớp."""
        return [tab_id for tab_id, tab in self.tabs.items() if tab.offer(event)]


def graph_user_name(canonical_key: str) -> str:
    """"<máy>:<tên>" -> "<tên>" (resolver đặt khoá user theo máy)."""
    return canonical_key.rsplit(":", 1)[-1]


# --- nhóm tự khám phá ------------------------------------------------------------


def discover_groups(conn, now_ts: float | None = None, *, window_s: float = 86400.0,
                    per_type: int = 15) -> list[dict]:
    """Nhóm để mở tab bằng một cú bấm, suy ra từ telemetry THẬT.

    - kind/source xuất hiện trong `window_s` (range scan trên index `ts`), và
      bảng `workspace_kinds` nhớ lần đầu thấy để đánh dấu cái MỚI.
    - thực thể IP / MAC / user từ evidence graph, sắp theo lần thấy gần nhất.
    - process theo `exe` của process_exec trong một giờ gần nhất (có 1 triệu
      thực thể process: liệt kê hết là vô nghĩa và đắt).
    Mọi truy vấn đều có cửa sổ thời gian và LIMIT.
    """
    now_ts = time.time() if now_ts is None else float(now_ts)
    since = now_ts - window_s
    groups: list[dict] = []
    rows = conn.execute(
        "SELECT source, kind, COUNT(*), MIN(ts), MAX(ts) FROM events WHERE ts >= ? "
        "GROUP BY source, kind ORDER BY COUNT(*) DESC LIMIT 200", (since,)).fetchall()
    for source, kind, _count, first, last in rows:
        conn.execute(
            "INSERT INTO workspace_kinds (source, kind, first_seen, last_seen) VALUES (?,?,?,?) "
            "ON CONFLICT(source, kind) DO UPDATE SET last_seen=MAX(last_seen, excluded.last_seen), "
            "first_seen=MIN(first_seen, excluded.first_seen)", (source, kind, first, last))
    known = {(s, k): f for s, k, f in conn.execute("SELECT source, kind, first_seen FROM workspace_kinds")}
    conn.commit()
    for source, kind, count, first, last in rows:
        first_ever = known.get((source, kind), first)
        groups.append({
            "group": "kind", "label": f"{kind} @ {source}", "count": int(count),
            "first_seen": float(first_ever), "last_seen": float(last),
            "new": float(first_ever) >= now_ts - NEW_WINDOW_S,
            "filter": WorkspaceFilter(kinds=frozenset({kind}), sources=frozenset({source})).to_dict(),
        })
    for filter_type, graph_type in GRAPH_TYPES.items():
        for key, first, last, observations in conn.execute(
                "SELECT canonical_key, first_seen, last_seen, observation_count FROM graph_entities "
                "WHERE entity_type=? ORDER BY last_seen DESC LIMIT ?", (graph_type, per_type)):
            # Khoá user trong graph là "<máy>:<tên>", còn event mang "<tên>":
            # bộ lọc phải dùng đúng thứ event mang, không thì tab không bao giờ khớp.
            if filter_type == "user":
                key = graph_user_name(str(key))
            groups.append({
                "group": filter_type, "label": f"{filter_type} {key}", "count": int(observations),
                "first_seen": float(first), "last_seen": float(last),
                "new": float(first) >= now_ts - NEW_WINDOW_S,
                "filter": WorkspaceFilter(entity_type=filter_type, entity_value=str(key)).to_dict(),
            })
    for exe, count, last in conn.execute(
            "SELECT json_extract(data, '$.exe') AS exe, COUNT(*), MAX(ts) FROM events "
            "WHERE ts >= ? AND kind = 'process_exec' AND exe IS NOT NULL AND exe != '' "
            "GROUP BY exe ORDER BY COUNT(*) DESC LIMIT ?", (now_ts - 3600.0, per_type)):
        groups.append({
            "group": "process", "label": f"process {exe}", "count": int(count),
            "first_seen": 0.0, "last_seen": float(last), "new": False,
            "filter": WorkspaceFilter(entity_type="process", entity_value=str(exe)).to_dict(),
        })
    return groups
