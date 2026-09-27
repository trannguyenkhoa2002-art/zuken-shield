"""Dữ liệu hiển thị của Live Workspace — hàm thuần, kiểm thử không cần Qt."""

from __future__ import annotations

import json
import time

from shield.security.workspace import ENTITY_KEYS, TabState
from shield.ui.evidence_view import event_subject, event_summary

COLUMNS = (("Thời gian", "Time"), ("Nguồn", "Source"), ("Loại", "Kind"),
           ("Đối tượng", "Subject"), ("Tóm tắt", "Summary"), ("Dòng gốc", "Raw line"))
REPLAY_WINDOWS = ((3600, "1h"), (86400, "24h"), (7 * 86400, "7d"))
_MODE = {"live": ("Trực tiếp", "Live"), "paused": ("Tạm dừng", "Paused"),
         "replay": ("Xem lại", "Replay")}


def _pick(pair: tuple[str, str], lang: str) -> str:
    return pair[0] if lang == "vi" else pair[1]


def headers(lang: str) -> list[str]:
    return [_pick(c, lang) for c in COLUMNS]


def row_values(event: dict) -> list[str]:
    ts = float(event.get("ts") or 0)
    return [
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
        str(event.get("source", "")), str(event.get("kind", "")),
        event_subject(event), event_summary(event),
        str(event.get("raw") or "—"),
    ]


def detail_text(event: dict) -> str:
    """Bản chuẩn hoá VÀ dòng gốc, cạnh nhau — không cái nào thay cái nào."""
    raw = str(event.get("raw") or "")
    return ("normalized:\n" + json.dumps(event.get("data") or {}, indent=2, sort_keys=True, default=str)
            + "\n\nraw:\n" + (raw if raw else "(no original line for this event)"))


def status_text(tab: TabState, lang: str) -> str:
    parts = [_pick(_MODE.get(tab.mode, (tab.mode, tab.mode)), lang),
             f"{len(tab.rows)} rows", f"{tab.matched} matched"]
    if tab.pending:
        parts.append(f"{len(tab.pending)} held")
    if tab.evicted:
        parts.append(f"{tab.evicted} scrolled out")
    if tab.dropped_while_paused:
        parts.append(f"{tab.dropped_while_paused} dropped while paused")
    return " · ".join(parts)


def entity_types() -> list[str]:
    return sorted(ENTITY_KEYS)


def group_label(group: dict) -> str:
    badge = "● NEW  " if group.get("new") else ""
    return f"{badge}{group.get('label', '')}  ({int(group.get('count', 0))})"
