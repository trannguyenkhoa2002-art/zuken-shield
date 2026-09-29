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


_TEXT = {
    "normalized": ("Bản chuẩn hoá", "Normalized"),
    "raw": ("Dòng gốc", "Raw line"),
    "no_raw": ("(event này không có dòng log gốc)", "(no original line for this event)"),
    "rows": ("{n} dòng", "{n} rows"),
    "matched": ("{n} khớp trực tiếp", "{n} live matched"),
    "held": ("{n} đang giữ", "{n} held"),
    "evicted": ("{n} đã trôi khỏi bảng", "{n} scrolled out"),
    "dropped": ("{n} bị bỏ khi tạm dừng", "{n} dropped while paused"),
    "new": ("● MỚI  ", "● NEW  "),
}


def _say(key: str, lang: str, **values) -> str:
    return _pick(_TEXT[key], lang).format(**values)


def detail_text(event: dict, lang: str = "en") -> str:
    """Bản chuẩn hoá VÀ dòng gốc, cạnh nhau — không cái nào thay cái nào."""
    raw = str(event.get("raw") or "")
    return (f"{_say('normalized', lang)}:\n"
            + json.dumps(event.get("data") or {}, indent=2, sort_keys=True, default=str)
            + f"\n\n{_say('raw', lang)}:\n" + (raw if raw else _say("no_raw", lang)))


def status_text(tab: TabState, lang: str) -> str:
    parts = [_pick(_MODE.get(tab.mode, (tab.mode, tab.mode)), lang),
             _say("rows", lang, n=len(tab.rows)), _say("matched", lang, n=tab.matched)]
    if tab.pending:
        parts.append(_say("held", lang, n=len(tab.pending)))
    if tab.evicted:
        parts.append(_say("evicted", lang, n=tab.evicted))
    if tab.dropped_while_paused:
        parts.append(_say("dropped", lang, n=tab.dropped_while_paused))
    return " · ".join(parts)


def entity_types() -> list[str]:
    return sorted(ENTITY_KEYS)


def group_label(group: dict, lang: str = "en") -> str:
    badge = _say("new", lang) if group.get("new") else ""
    return f"{badge}{group.get('label', '')}  ({int(group.get('count', 0))})"
