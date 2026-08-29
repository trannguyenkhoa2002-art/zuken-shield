"""Query service read-only cho evidence graph (KE-HOACH-SHIELD-2.0.md mục 1.4).

Đây là ranh giới sẽ đứng giữa AI analyst và database ở Phase 2. Nó được xây từ
bây giờ, TRƯỚC khi có model nào, vì một ranh giới thêm vào sau khi đã có người
đi vòng qua nó thì không còn là ranh giới.

Bốn thứ mọi câu truy vấn ở đây đều có, không có ngoại lệ:

1. **Trần cứng.** Không câu nào trả về không giới hạn. Kể cả khi caller xin
   một tỉ dòng, kể cả khi caller là mã của chính Shield.
2. **Timeout.** Một câu chạy quá lâu bị cắt, không kéo cả agent xuống theo.
3. **Redaction.** Mật khẩu, token, khoá riêng bị che TRƯỚC khi rời khỏi lớp này.
4. **Audit.** Ai hỏi gì, trả về bao nhiêu dòng, mất bao lâu.

Và một thứ không có: **không nhận SQL**. Người gọi chọn một trong các phương
thức dưới đây và truyền tham số; không có đường nào để một chuỗi từ bên ngoài
trở thành một phần của câu lệnh. Mục 3.2 của kế hoạch: "Text do AI sinh không
bao giờ được dùng làm shell command, path, SQL hoặc rule."
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from shield.common.secrets import REDACTED as _REDACTED
from shield.common.secrets import redact as _redact
from shield.evidence.graph import MAX_LIMIT, EvidenceGraph
from shield.evidence.models import ENTITY_TYPES, RELATIONS

logger = logging.getLogger("shield.evidence.queries")

DEFAULT_LIMIT = 100
DEFAULT_TIMEOUT_S = 5.0

# --- tìm event (Expert Evidence) ---
#
# Cửa sổ thời gian là BẮT BUỘC, không có mặc định "tất cả". Bảng `events` trên
# máy thật đã 1,84 triệu dòng và chỉ lớn thêm; một câu truy vấn không có ràng
# buộc thời gian là một câu quét toàn bảng đang chờ tới lượt.
MAX_WINDOW_S = 7 * 86400
# Trần trang. `MAX_LIMIT` (500) dùng chung với phần đồ thị.
DEFAULT_PAGE = 100
# Trường được phép lọc bằng `json_extract`. Danh sách ĐÓNG: một tên trường tự
# do đi thẳng vào biểu thức SQL là một bề mặt tấn công, còn một tên trường sai
# thì im lặng trả về rỗng và trông y hệt "không có gì xảy ra".
JSON_FILTERS = {
    "pid": "$.pid",
    "ip": "$.remote_ip",
    "port": "$.remote_port",
    "host": "$.host",
    "uid": "$.uid",
}
MAX_DEPTH = 3

# Node "trung tâm": đo trên dữ liệu thật, thực thể `host` của máy cục bộ có bậc
# 23.588 trên 23.598 cạnh — gần như MỌI cạnh đều chạm vào nó, vì mọi tiến trình
# đều `ran_on` cùng một máy.
#
# Đi xuyên qua một node như thế trong truy vấn nhiều bước biến "tiến trình này
# liên quan tới gì" thành "mọi thứ từng chạy trên máy này". Kết quả vẫn dưới
# trần cứng, nên nhìn thì an toàn — nhưng 500 dòng ngẫu nhiên trong 23 nghìn
# là tệ hơn không trả gì: nó trông như một câu trả lời.
#
# Node trung tâm vẫn được TRẢ VỀ như một cạnh kề (nó là sự thật), chỉ không
# được MỞ RỘNG tiếp.
HUB_DEGREE = 500

# Luật che dùng CHUNG với đường gửi đi — xem shield/common/secrets.py. Trước
# đây mỗi đường có bộ luật riêng, chúng lệch nhau, và bộ yếu hơn được dùng ở
# đúng chỗ nhật ký lời gọi tool.
REDACTED = _REDACTED


def redact(value):
    """Che bí mật trong một giá trị bất kỳ, đệ quy."""
    return _redact(value)


@dataclass
class QueryAudit:
    """Nhật ký truy vấn. Ở Phase 2 đây là bằng chứng model đã đọc những gì."""

    entries: list[dict] = field(default_factory=list)
    max_entries: int = 1000

    def record(self, name: str, params: dict, rows: int, elapsed_s: float,
               caller: str, error: str = "") -> None:
        self.entries.append({
            "query": name, "params": redact(params), "rows": rows,
            "elapsed_s": round(elapsed_s, 6), "caller": caller,
            "ts": time.time(), "error": error,
        })
        # Chặn trần: nhật ký không được trở thành chỗ rò bộ nhớ. Bỏ dòng CŨ
        # nhất, vì khi điều tra người ta cần những gì vừa xảy ra.
        if len(self.entries) > self.max_entries:
            del self.entries[: len(self.entries) - self.max_entries]


class QueryTimeout(RuntimeError):
    """Câu truy vấn vượt quá ngân sách thời gian."""


class EvidenceQueries:
    """Bề mặt đọc duy nhất của evidence graph."""

    def __init__(self, conn, *, caller: str = "shield", timeout_s: float = DEFAULT_TIMEOUT_S,
                 audit: QueryAudit | None = None) -> None:
        self.conn = conn
        self.graph = EvidenceGraph(conn)
        self.caller = caller
        self.timeout_s = max(0.1, float(timeout_s))
        self.audit = audit if audit is not None else QueryAudit()

    # --- hạ tầng ---

    @staticmethod
    def _bounded(limit) -> int:
        """Trần cứng. Xin một tỉ dòng vẫn nhận về nhiều nhất MAX_LIMIT."""
        try:
            value = int(limit)
        except (TypeError, ValueError):
            return DEFAULT_LIMIT
        return max(1, min(value, MAX_LIMIT))

    def _run(self, name: str, params: dict, fn):
        started = time.monotonic()
        deadline = started + self.timeout_s
        try:
            rows = fn(deadline)
        except QueryTimeout as exc:
            self.audit.record(name, params, 0, time.monotonic() - started, self.caller, str(exc))
            raise
        except Exception as exc:  # noqa: BLE001 — nhật ký phải ghi cả lỗi lạ
            self.audit.record(name, params, 0, time.monotonic() - started,
                              self.caller, f"{type(exc).__name__}: {exc}")
            raise
        rows = redact(rows)
        self.audit.record(name, params, len(rows) if isinstance(rows, list) else 1,
                          time.monotonic() - started, self.caller)
        return rows

    def _degree(self, entity_id: str) -> int:
        """Bậc của một node. Đếm có TRẦN: chỉ cần biết 'lớn hơn HUB_DEGREE hay
        không', và đếm hết 23 nghìn cạnh để trả lời câu đó là lãng phí."""
        row = self.conn.execute(
            "SELECT COUNT(*) FROM (SELECT edge_id FROM graph_edges "
            "WHERE src_id=? OR dst_id=? LIMIT ?)",
            (entity_id, entity_id, HUB_DEGREE + 1),
        ).fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _check_deadline(deadline: float) -> None:
        if time.monotonic() > deadline:
            raise QueryTimeout("query vượt quá ngân sách thời gian")

    # --- thực thể ---

    def get_entity(self, entity_id: str) -> dict | None:
        return self._run("get_entity", {"entity_id": entity_id},
                         lambda _d: self.graph.get_entity(str(entity_id)))

    def find_entity(self, entity_type: str, canonical_key: str) -> dict | None:
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"loại thực thể không hợp lệ: {entity_type!r}")
        return self._run("find_entity", {"entity_type": entity_type, "key": canonical_key},
                         lambda _d: self.graph.find_entity(entity_type, str(canonical_key)))

    def list_entities(self, entity_type: str, limit: int = DEFAULT_LIMIT) -> list[dict]:
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"loại thực thể không hợp lệ: {entity_type!r}")
        capped = self._bounded(limit)

        def run(_deadline):
            rows = self.conn.execute(
                "SELECT entity_id,entity_type,canonical_key,attributes,aliases,first_seen,"
                "last_seen,trust,provenance,criticality,resolution_confidence,observation_count "
                "FROM graph_entities WHERE entity_type=? ORDER BY last_seen DESC LIMIT ?",
                (entity_type, capped),
            ).fetchall()
            from shield.evidence.graph import _entity_row
            return [_entity_row(row) for row in rows]

        return self._run("list_entities", {"entity_type": entity_type, "limit": capped}, run)

    # --- quan hệ ---

    def get_neighbors(self, entity_id: str, relations=None, depth: int = 1,
                      limit: int = DEFAULT_LIMIT, direction: str = "both") -> list[dict]:
        """Cạnh kề, mở rộng tối đa `MAX_DEPTH` bước.

        Độ sâu bị chặn cứng chứ không phải "mặc định nhỏ": mỗi bước nhân số
        cạnh lên, và một truy vấn sâu trên một node trung tâm (một địa chỉ IP
        mà cả mạng cùng nói chuyện) sẽ kéo về nửa graph.
        """
        if relations:
            unknown = {str(r) for r in relations} - RELATIONS
            if unknown:
                raise ValueError(f"quan hệ không hợp lệ: {sorted(unknown)}")
        if direction not in {"in", "out", "both"}:
            raise ValueError(f"chiều không hợp lệ: {direction!r}")
        capped = self._bounded(limit)
        levels = max(1, min(int(depth), MAX_DEPTH))

        def run(deadline):
            seen_edges: dict[str, dict] = {}
            frontier = {str(entity_id)}
            visited: set[str] = set()
            for level in range(levels):
                self._check_deadline(deadline)
                next_frontier: set[str] = set()
                for node in frontier - visited:
                    visited.add(node)
                    # Bước đầu luôn đi, kể cả từ chính node trung tâm: người
                    # dùng hỏi thẳng về nó thì phải được trả lời.
                    if level > 0 and self._degree(node) > HUB_DEGREE:
                        continue
                    for edge in self.graph.neighbors(node, relations, capped, direction):
                        seen_edges[edge["edge_id"]] = edge
                        next_frontier.update((edge["src_id"], edge["dst_id"]))
                        if len(seen_edges) >= capped:
                            return list(seen_edges.values())[:capped]
                frontier = next_frontier
                if not frontier:
                    break
            return list(seen_edges.values())[:capped]

        return self._run("get_neighbors",
                         {"entity_id": entity_id, "depth": levels, "limit": capped,
                          "direction": direction, "relations": sorted(relations or ())},
                         run)

    def get_process_ancestry(self, entity_id: str, limit: int = 32) -> list[dict]:
        """Chuỗi tiến trình cha, từ gần nhất lên trên.

        Có trần vòng lặp riêng vì dữ liệu hỏng có thể tạo chu trình cha-con, và
        một vòng lặp đi theo con trỏ cha mà không có trần sẽ chạy mãi.
        """
        capped = self._bounded(limit)

        def run(deadline):
            chain, current, seen = [], str(entity_id), {str(entity_id)}
            for _ in range(capped):
                self._check_deadline(deadline)
                parents = [e for e in self.graph.neighbors(current, ["spawned"], 8, "in")
                           if e["dst_id"] == current]
                if not parents:
                    break
                edge = parents[0]
                if edge["src_id"] in seen:
                    break   # chu trình
                seen.add(edge["src_id"])
                node = self.graph.get_entity(edge["src_id"])
                chain.append({"entity": node, "edge": edge})
                current = edge["src_id"]
            return chain

        return self._run("get_process_ancestry", {"entity_id": entity_id, "limit": capped}, run)

    def get_file_history(self, entity_id: str, limit: int = DEFAULT_LIMIT) -> list[dict]:
        capped = self._bounded(limit)
        return self._run(
            "get_file_history", {"entity_id": entity_id, "limit": capped},
            lambda _d: self.graph.neighbors(str(entity_id), ["wrote", "has_hash"], capped, "both"),
        )

    def get_user_login_history(self, entity_id: str, limit: int = DEFAULT_LIMIT) -> list[dict]:
        capped = self._bounded(limit)
        return self._run(
            "get_user_login_history", {"entity_id": entity_id, "limit": capped},
            lambda _d: self.graph.neighbors(str(entity_id), ["logged_into", "belongs_to"],
                                            capped, "both"),
        )

    def get_network_peers(self, entity_id: str, limit: int = DEFAULT_LIMIT) -> list[dict]:
        capped = self._bounded(limit)
        return self._run(
            "get_network_peers", {"entity_id": entity_id, "limit": capped},
            lambda _d: self.graph.neighbors(str(entity_id), ["connected_to"], capped, "both"),
        )

    # --- bằng chứng ---

    def get_evidence(self, evidence_ref: str) -> dict | None:
        return self._run("get_evidence", {"evidence_ref": evidence_ref},
                         lambda _d: self.graph.evidence_for(str(evidence_ref)))

    def get_entity_timeline(self, entity_id: str, window_s: float = 3600.0,
                            limit: int = DEFAULT_LIMIT) -> list[dict]:
        """Mọi cạnh chạm vào thực thể này, sắp theo thời gian TĂNG dần.

        Tăng dần chứ không giảm: người điều tra đọc một sự việc theo chiều nó
        đã xảy ra. Danh sách "mới nhất trước" là để theo dõi trực tiếp, không
        phải để dựng lại một chuỗi.
        """
        capped = self._bounded(limit)

        def run(_deadline):
            edges = self.graph.neighbors(str(entity_id), None, capped, "both")
            if not edges:
                return []
            newest = max(edge["last_seen"] for edge in edges)
            cutoff = newest - max(1.0, float(window_s))
            inside = [edge for edge in edges if edge["last_seen"] >= cutoff]
            return sorted(inside, key=lambda edge: edge["first_seen"])

        return self._run("get_entity_timeline",
                         {"entity_id": entity_id, "window_s": window_s, "limit": capped}, run)

    # --- tìm event: đường kiểm chứng độc lập cho chuyên gia ---

    @staticmethod
    def _parse_cursor(cursor: str) -> tuple[float, int] | None:
        """`"<ts>:<id>"` -> (ts, id). Sai định dạng thì TỪ CHỐI, không bỏ qua.

        Bỏ qua một con trỏ hỏng nghĩa là âm thầm trả về trang ĐẦU trong khi
        người gọi tưởng mình đang đi tiếp — và họ sẽ đọc mãi cùng một trang mà
        không biết.
        """
        if not cursor:
            return None
        text = str(cursor)
        if text.count(":") != 1:
            raise ValueError("cursor không hợp lệ")
        left, right = text.split(":", 1)
        try:
            return float(left), int(right)
        except ValueError as exc:
            raise ValueError("cursor không hợp lệ") from exc

    def search_events(self, *, start_time, end_time, kind: str = "", source: str = "",
                      origin: str = "", event_id: str = "", incident_id: str = "",
                      alert_id=None, filters: dict | None = None,
                      limit: int = DEFAULT_PAGE, cursor: str = "") -> dict:
        """Tìm event đã chuẩn hoá trong một cửa sổ thời gian BẮT BUỘC.

        Trả về `{"events": [...], "next_cursor": str, "window_s": float}`.

        Thứ tự `ts DESC, id DESC` — thêm `id` không phải để đẹp: nhiều event có
        thể mang cùng một mốc thời gian, và một con trỏ chỉ dựa trên `ts` sẽ
        hoặc bỏ sót hoặc lặp lại đúng những dòng đó.

        Mọi lọc `json_extract` chỉ chạy SAU khi cửa sổ thời gian đã thu hẹp tập
        dòng bằng index — không bao giờ trên toàn bảng.
        """
        try:
            start, end = float(start_time), float(end_time)
        except (TypeError, ValueError) as exc:
            raise ValueError("khoảng thời gian không hợp lệ") from exc
        if not end > start:
            raise ValueError("end_time phải lớn hơn start_time")
        window = end - start
        if window > MAX_WINDOW_S:
            raise ValueError(
                f"cửa sổ {window / 86400:.1f} ngày vượt trần {MAX_WINDOW_S / 86400:.0f} ngày")
        capped = self._bounded(limit)
        after = self._parse_cursor(cursor)

        where = ["ts >= ?", "ts <= ?"]
        params: list = [start, end]
        if kind:
            where.append("kind = ?")
            params.append(str(kind))
        if source:
            where.append("source = ?")
            params.append(str(source))
        if origin:
            where.append("origin = ?")
            params.append(str(origin))
        if event_id:
            # `event_id != ''` là điều kiện để SQLite dùng được index MỘT PHẦN
            # trên cột này. Thiếu nó: 221 ms quét toàn bảng thay vì 0,14 ms.
            where.append("event_id != '' AND event_id = ?")
            params.append(str(event_id))
        for name, value in (filters or {}).items():
            if name not in JSON_FILTERS:
                raise ValueError(f"trường lọc không được phép: {name!r}")
            if value in (None, ""):
                continue
            where.append(f"json_extract(data, '{JSON_FILTERS[name]}') = ?")
            params.append(value)
        if after is not None:
            where.append("(ts < ? OR (ts = ? AND id < ?))")
            params.extend([after[0], after[0], after[1]])

        scope = {"start_time": start, "end_time": end, "kind": kind, "source": source,
                 "origin": origin, "event_id": event_id, "incident_id": incident_id,
                 "alert_id": alert_id, "filters": dict(filters or {}),
                 "limit": capped, "cursor": cursor}

        def run(deadline):
            clauses, values = list(where), list(params)
            if incident_id or alert_id is not None:
                refs = self._event_refs_for(incident_id, alert_id)
                if not refs:
                    return []
                placeholders = ",".join("?" * len(refs))
                clauses.append(f"event_id != '' AND event_id IN ({placeholders})")
                values.extend(refs)
            self._check_deadline(deadline)
            rows = self.conn.execute(
                "SELECT id, event_id, ts, source, kind, data, origin, trust, "
                "ts_ingested, content_hash, signature_status, collector_version "
                f"FROM events WHERE {' AND '.join(clauses)} "
                "ORDER BY ts DESC, id DESC LIMIT ?",
                values + [capped],
            ).fetchall()
            self._check_deadline(deadline)
            return [self._event_row(row) for row in rows]

        events = self._run("search_events", scope, run)
        next_cursor = ""
        if len(events) == capped:
            last = events[-1]
            next_cursor = f"{last['ts']}:{last['row_id']}"
        return {"events": events, "next_cursor": next_cursor, "window_s": window}

    def _event_refs_for(self, incident_id: str, alert_id) -> list[str]:
        """`event_id` liên quan tới một incident hoặc một alert.

        Cả hai đều tra qua khoá chính đã có — `incident_refs` và `alerts.id` —
        không có bảng ánh xạ nào mới.
        """
        refs: set[str] = set()
        if incident_id:
            refs |= {row[0] for row in self.conn.execute(
                "SELECT ref_id FROM incident_refs WHERE incident_id=? AND ref_kind='evidence'",
                (str(incident_id),)).fetchall()}
        if alert_id is not None:
            row = self.conn.execute(
                "SELECT json_extract(evidence, '$.event_id') FROM alerts WHERE id=?",
                (int(alert_id),)).fetchone()
            if row and row[0]:
                refs.add(str(row[0]))
        return sorted(refs)[:MAX_LIMIT]

    @staticmethod
    def _event_row(row) -> dict:
        import json as _json

        try:
            data = _json.loads(row[5])
        except (TypeError, ValueError):
            data = {"_unparsable": str(row[5])[:4096]}
        return {
            "row_id": row[0], "event_id": row[1], "ts": row[2], "source": row[3],
            "kind": row[4], "data": data, "origin": row[6], "trust": row[7],
            "ts_ingested": row[8], "content_hash": row[9],
            "signature_status": row[10], "collector_version": row[11],
            # Shield KHÔNG lưu payload gốc — bảng `events` chỉ có bản đã chuẩn
            # hoá. Nói ra bằng dữ liệu, để giao diện không phải đoán, và để
            # không ai dựng lại một "raw" giả từ các trường đã chuẩn hoá.
            "raw_retained": False,
        }

    def get_event(self, event_id: str) -> dict | None:
        """Một event kèm mọi thứ truy ngược được từ nó.

        Đây là đích của chuỗi Incident -> alert -> evidence ref -> event, và nó
        không gọi AI ở bất kỳ bước nào.
        """
        wanted = str(event_id)
        if not wanted:
            raise ValueError("event_id rỗng")

        def run(deadline):
            row = self.conn.execute(
                "SELECT id, event_id, ts, source, kind, data, origin, trust, "
                "ts_ingested, content_hash, signature_status, collector_version "
                "FROM events WHERE event_id != '' AND event_id = ?", (wanted,)).fetchone()
            if row is None:
                return None
            self._check_deadline(deadline)
            event = self._event_row(row)
            event["alert_ids"] = [r[0] for r in self.conn.execute(
                "SELECT id FROM alerts WHERE json_extract(evidence, '$.event_id') = ? "
                "ORDER BY id LIMIT ?", (wanted, MAX_LIMIT)).fetchall()]
            event["incident_ids"] = [r[0] for r in self.conn.execute(
                "SELECT incident_id FROM incident_refs "
                "WHERE ref_kind='evidence' AND ref_id=? ORDER BY incident_id LIMIT ?",
                (wanted, MAX_LIMIT)).fetchall()]
            self._check_deadline(deadline)
            event["evidence"] = self.graph.evidence_for(f"event:{wanted}")
            return event

        return self._run("get_event", {"event_id": wanted}, run)

    def counts(self) -> dict:
        return self._run("counts", {}, lambda _d: self.graph.counts())

    def integrity_report(self, limit: int = MAX_LIMIT) -> dict:
        """Graph có đang giữ đúng bất biến của nó không.

        Gate Phase 1: "Không có orphan evidence reference." Đây là cách hỏi câu
        đó trên dữ liệu thật, và nó nên chạy được từ UI chứ không chỉ từ test.
        """
        def run(_deadline):
            orphans = self.graph.orphan_edges(self._bounded(limit))
            return {"orphan_edges": orphans, "orphan_count": len(orphans),
                    **self.graph.counts()}

        return self._run("integrity_report", {"limit": limit}, run)
