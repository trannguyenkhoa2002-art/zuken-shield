"""Incident case workflow, unified timelines and process graphs."""

from __future__ import annotations

import time
import uuid


CASE_STATES = {"open", "investigating", "resolved", "false_positive"}


def build_process_graph(events: list[dict]) -> dict:
    nodes, edges = {}, set()
    for event in events:
        data = event.get("data") or {}
        if event.get("kind") not in {"process_started", "process_exec", "process_exit"}:
            continue
        pid = data.get("pid")
        if pid is None:
            continue
        node_id = str(data.get("process_identity") or f"{pid}:{data.get('start_ticks', '?')}")
        nodes[node_id] = {"id": node_id, "pid": int(pid), "exe": str(data.get("exe", "")), "user": data.get("uid", data.get("user"))}
        ppid = data.get("ppid")
        if ppid not in (None, 0, 1):
            edges.add((str(ppid), node_id))
    return {"nodes": list(nodes.values()), "edges": [{"parent": a, "child": b} for a, b in sorted(edges)]}


class InvestigationService:
    def __init__(self, store) -> None:
        self.store = store

    def create_case(self, title: str, subject: str, alert_rules: list[str] | None = None) -> dict:
        case = {"case_id": uuid.uuid4().hex, "title": title[:200], "subject": subject[:300],
                "state": "open", "created_ts": time.time(), "updated_ts": time.time(),
                "alert_rules": list(dict.fromkeys(alert_rules or []))[:100]}
        self.store.save_case(case)
        return case

    def set_state(self, case_id: str, state: str) -> None:
        if state not in CASE_STATES:
            raise ValueError("invalid case state")
        self.store.update_case_state(case_id, state)

    def add_note(self, case_id: str, author: str, text: str) -> None:
        text = text.strip()
        if not text or len(text) > 4000:
            raise ValueError("invalid case note")
        self.store.add_case_note(case_id, author[:100], text)

    def timeline(self, subject: str, since_ts: float = 0, limit: int = 1000) -> list[dict]:
        return self.store.search_security_records(subject, since_ts=since_ts, limit=limit)
