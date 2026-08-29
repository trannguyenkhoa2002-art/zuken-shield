"""Lưu và đọc evidence graph (KE-HOACH-SHIELD-2.0.md mục 1.3).

Bất biến mà lớp này ép, và lý do từng cái tồn tại:

- **Không cạnh nào không có bằng chứng.** `Edge` đã chặn ở tầng kiểu; ở đây
  chặn thêm một lần nữa khi ghi, vì dữ liệu cũng đi vào từ đường phục hồi và
  đường nhập liệu, không chỉ từ resolver.
- **Không evidence_ref mồ côi.** Mỗi ref phải có một dòng trong
  `evidence_objects`. Một cạnh trỏ tới event đã bị xoá theo hạn lưu trữ là một
  cạnh không kiểm chứng lại được — nó phải biến mất cùng bằng chứng của nó.
- **Trust không tự lên qua hợp nhất.** Cạnh giữ trust của bằng chứng SINH RA
  nó. Nó không bao giờ đọc trust của thực thể hai đầu. Đây là thứ chặn kịch
  bản: kẻ tấn công bắn syslog giả trùng khoá định danh một máy đã quan sát cục
  bộ, rồi mọi khẳng định của hắn được nâng lên mức tin cậy của máy đó.
"""

from __future__ import annotations

import json
import time

from shield.common.models import trust_rank
from shield.evidence.models import Edge, Entity, EvidenceKind, merge_trust

GRAPH_SCHEMA = """
-- CHỈ dùng cho bằng chứng KHÔNG phải event: alert, incident, threat-intel.
--
-- Event không có dòng ở đây, có chủ ý. Bảng `events` đã giữ event_id (unique),
-- ts, origin, trust và content_hash — chép lại chúng sang đây là hai nguồn sự
-- thật cho cùng một sự việc, và khi hai nguồn lệch nhau thì không có cách nào
-- biết bên nào đúng. Đo trên 50 nghìn event: một dòng/event tốn 1131 byte/event,
-- tức khoảng 2 GB mỗi ngày ở nhịp thật của máy này. Bỏ nó đi còn ~380 byte.
--
-- Lợi ích thứ hai quan trọng hơn dung lượng: khi hạn lưu trữ xoá một event,
-- mọi tham chiếu tới nó lập tức thành mồ côi và `prune()` gỡ đúng những cạnh
-- không còn kiểm chứng lại được. Nếu evidence_objects giữ bản sao riêng, cạnh
-- sẽ sống sót sau khi bằng chứng đã biến mất — đúng thứ gate Phase 1 cấm.
CREATE TABLE IF NOT EXISTS evidence_objects (
    evidence_ref TEXT PRIMARY KEY,
    evidence_kind TEXT NOT NULL,
    ts REAL NOT NULL,
    origin TEXT NOT NULL DEFAULT 'local',
    trust TEXT NOT NULL DEFAULT 'local',
    content_hash TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS graph_entities (
    entity_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}',
    aliases TEXT NOT NULL DEFAULT '[]',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    trust TEXT NOT NULL DEFAULT 'local',
    -- Bậc tin cậy dạng SỐ. Cần thiết vì SQLite không so được "local" với
    -- "unauthenticated" theo ngữ nghĩa — so chuỗi sẽ cho "authenticated" nhỏ
    -- hơn "local" đúng theo bảng chữ cái và sai theo mọi nghĩa khác.
    trust_rank INTEGER NOT NULL DEFAULT 0,
    provenance TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT 'normal',
    resolution_confidence REAL NOT NULL DEFAULT 1.0,
    observation_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(entity_type, canonical_key)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id TEXT PRIMARY KEY,
    src_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    dst_id TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    evidence_kind TEXT NOT NULL DEFAULT 'observed',
    trust TEXT NOT NULL DEFAULT 'local',
    derived_by TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    observation_count INTEGER NOT NULL DEFAULT 1,
    attributes TEXT NOT NULL DEFAULT '{}',
    UNIQUE(src_id, relation, dst_id)
);
"""

GRAPH_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_graph_entities_type ON graph_entities(entity_type, last_seen);
CREATE INDEX IF NOT EXISTS idx_graph_entities_key ON graph_entities(canonical_key);
-- Đi xuôi và đi ngược đều phải nhanh: "tiến trình này nối tới đâu" và "ai đã
-- nối tới địa chỉ này" là cùng một câu hỏi nhìn từ hai phía, và câu thứ hai
-- mới là câu người điều tra hỏi.
CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(src_id, relation, last_seen);
CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(dst_id, relation, last_seen);
CREATE INDEX IF NOT EXISTS idx_graph_edges_ts ON graph_edges(last_seen);
CREATE INDEX IF NOT EXISTS idx_evidence_ts ON evidence_objects(ts);
"""

# Giới hạn cứng cho mọi câu đọc. Mục 1.4: "Mỗi query phải có hard limit."
MAX_LIMIT = 500
MAX_EVIDENCE_REFS_PER_EDGE = 32


class EvidenceGraph:
    """Đọc/ghi graph trên cùng connection với Store."""

    def __init__(self, conn) -> None:
        self.conn = conn

    # --- ghi ---

    def record_evidence(self, evidence_ref: str, *, evidence_kind: str = EvidenceKind.OBSERVED,
                        ts: float = 0.0, origin: str = "local", trust: str = "local",
                        content_hash: str = "", summary: str = "") -> None:
        if evidence_kind not in EvidenceKind.ALL:
            raise ValueError(f"loại bằng chứng không hợp lệ: {evidence_kind!r}")
        self.conn.execute(
            "INSERT INTO evidence_objects(evidence_ref,evidence_kind,ts,origin,trust,"
            "content_hash,summary) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(evidence_ref) DO UPDATE SET ts=MIN(ts,excluded.ts)",
            (evidence_ref, evidence_kind, ts or time.time(), origin, trust,
             content_hash, summary[:500]),
        )

    def upsert_entity(self, entity: Entity) -> str:
        """Hợp nhất một quan sát vào thực thể.

        `first_seen` lấy nhỏ hơn, `last_seen` lấy lớn hơn — nghe hiển nhiên,
        nhưng bản backfill của 1.1 từng đóng dấu `time.time()` lên cả hai và
        làm 57 thiết bị tắt từ tuần trước hiện lên như đang online.

        `trust` lấy mức CAO HƠN, và điều đó an toàn vì trust ở đây chỉ nói
        "mức bằng chứng tốt nhất từng thấy VỀ SỰ TỒN TẠI của thực thể này".
        Nó không lan sang cạnh: mọi khẳng định về việc thực thể này đã LÀM gì
        đều mang trust riêng của bằng chứng cho khẳng định đó.
        """
        attributes = {k: v for k, v in entity.attributes.items() if v not in (None, "")}
        self.conn.execute(
            "INSERT INTO graph_entities(entity_id,entity_type,canonical_key,attributes,"
            "aliases,first_seen,last_seen,trust,trust_rank,provenance,criticality,"
            "resolution_confidence,observation_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1) "
            "ON CONFLICT(entity_id) DO UPDATE SET "
            "  first_seen=MIN(first_seen,excluded.first_seen),"
            "  last_seen=MAX(last_seen,excluded.last_seen),"
            "  observation_count=observation_count+1,"
            "  attributes=excluded.attributes,"
            "  trust=CASE WHEN excluded.trust_rank>trust_rank THEN excluded.trust ELSE trust END,"
            "  trust_rank=MAX(trust_rank,excluded.trust_rank)",
            (entity.entity_id, entity.entity_type, entity.canonical_key,
             json.dumps(attributes, sort_keys=True, default=str),
             json.dumps(list(entity.aliases)), entity.first_seen or time.time(),
             entity.last_seen or time.time(), entity.trust, trust_rank(entity.trust),
             entity.provenance, entity.criticality, entity.resolution_confidence),
        )
        return entity.entity_id

    def upsert_edge(self, edge: Edge) -> str:
        """Ghi một cạnh, hợp nhất với cạnh cùng (src, relation, dst) nếu đã có.

        Số evidence_ref bị chặn trần: một cạnh được quan sát mười nghìn lần
        không cần mười nghìn tham chiếu, và không chặn thì một tiến trình ồn ào
        sẽ thổi một dòng lên vài megabyte.
        """
        if not edge.evidence_refs:
            raise ValueError("cạnh phải có ít nhất một evidence_ref")
        self._require_evidence_exists(edge.evidence_refs)
        row = self.conn.execute(
            "SELECT evidence_refs,trust,confidence,evidence_kind FROM graph_edges WHERE edge_id=?",
            (edge.edge_id,),
        ).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO graph_edges(edge_id,src_id,relation,dst_id,evidence_refs,"
                "evidence_kind,trust,derived_by,first_seen,last_seen,confidence,"
                "observation_count,attributes) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?)",
                (edge.edge_id, edge.src_id, edge.relation, edge.dst_id,
                 json.dumps(list(edge.evidence_refs[:MAX_EVIDENCE_REFS_PER_EDGE])),
                 edge.evidence_kind, edge.trust, edge.derived_by,
                 edge.first_seen or time.time(), edge.last_seen or time.time(),
                 edge.confidence, json.dumps(edge.attributes, sort_keys=True, default=str)),
            )
            return edge.edge_id

        existing_refs = json.loads(row[0])
        merged = list(dict.fromkeys([*existing_refs, *edge.evidence_refs]))[:MAX_EVIDENCE_REFS_PER_EDGE]
        # Cạnh được nhiều bằng chứng độc lập chống lưng thì đáng tin hơn — nhưng
        # trần là 1.0 và mức tăng nhỏ dần, để "quan sát nhiều lần" không biến
        # thành "chắc chắn". Lặp lại một quan sát không phải là một bằng chứng
        # mới; nó chỉ là cùng một bằng chứng nói lại.
        confidence = min(1.0, max(row[2], edge.confidence) + 0.01 * (len(merged) - len(existing_refs)))
        kind = row[3] if EvidenceKind.RANK.get(row[3], 0) >= EvidenceKind.RANK.get(edge.evidence_kind, 0) else edge.evidence_kind
        self.conn.execute(
            "UPDATE graph_edges SET evidence_refs=?,trust=?,confidence=?,evidence_kind=?,"
            "first_seen=MIN(first_seen,?),last_seen=MAX(last_seen,?),"
            "observation_count=observation_count+1 WHERE edge_id=?",
            (json.dumps(merged), merge_trust(row[1], edge.trust), confidence, kind,
             edge.first_seen or time.time(), edge.last_seen or time.time(), edge.edge_id),
        )
        return edge.edge_id

    def _resolves(self, ref: str) -> bool:
        """Tham chiếu này có trỏ tới thứ gì còn tồn tại không.

        `event:<id>` tra thẳng bảng `events` — nguồn sự thật duy nhất cho event.
        Mọi loại khác tra `evidence_objects`.
        """
        if ref.startswith("event:"):
            # `AND event_id != ''` KHÔNG thừa. Index trên event_id là index MỘT
            # PHẦN (`WHERE event_id != ''`) vì 1,1 triệu dòng cũ mang chuỗi
            # rỗng. SQLite chỉ dùng được index một phần khi mệnh đề WHERE của
            # câu truy vấn CHỨNG MINH được vị từ của index — và `event_id = ?`
            # với tham số ràng buộc thì không chứng minh được gì lúc lập kế
            # hoạch. Kết quả: quét toàn bảng cho MỖI cạnh ghi vào graph.
            #
            # Đo trên database production 1,1 triệu dòng: 1658 ms một lần tra,
            # xuống 0,085 ms sau khi thêm điều kiện. Agent đang đốt trọn một
            # nhân CPU liên tục vì đúng dòng này.
            return self.conn.execute(
                "SELECT 1 FROM events WHERE event_id=? AND event_id!=''",
                (ref.split(":", 1)[1],)
            ).fetchone() is not None
        return self.conn.execute(
            "SELECT 1 FROM evidence_objects WHERE evidence_ref=?", (ref,)
        ).fetchone() is not None

    def _require_evidence_exists(self, refs) -> None:
        missing = [ref for ref in refs if not self._resolves(ref)]
        if missing:
            raise ValueError(f"evidence_ref mồ côi: {missing}")

    def ingest(self, entities, edges) -> tuple[int, int]:
        for entity in entities:
            self.upsert_entity(entity)
        written = 0
        for edge in edges:
            self.upsert_edge(edge)
            written += 1
        return len(entities), written

    # --- đọc (mọi câu đều có trần cứng) ---

    def get_entity(self, entity_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT entity_id,entity_type,canonical_key,attributes,aliases,first_seen,"
            "last_seen,trust,provenance,criticality,resolution_confidence,observation_count "
            "FROM graph_entities WHERE entity_id=?", (entity_id,),
        ).fetchone()
        return _entity_row(row) if row else None

    def find_entity(self, entity_type: str, canonical_key: str) -> dict | None:
        row = self.conn.execute(
            "SELECT entity_id,entity_type,canonical_key,attributes,aliases,first_seen,"
            "last_seen,trust,provenance,criticality,resolution_confidence,observation_count "
            "FROM graph_entities WHERE entity_type=? AND canonical_key=?",
            (entity_type, canonical_key),
        ).fetchone()
        return _entity_row(row) if row else None

    def neighbors(self, entity_id: str, relations=None, limit: int = 100,
                  direction: str = "both") -> list[dict]:
        """Cạnh kề. `direction` là 'out', 'in' hoặc 'both'.

        Chiều `in` không phải tiện nghi: "ai đã nối tới địa chỉ này" là câu hỏi
        người điều tra thật sự hỏi, và nó luôn là chiều ngược.
        """
        limit = max(1, min(int(limit), MAX_LIMIT))
        clauses, params = [], []
        if direction in {"out", "both"}:
            clauses.append("src_id=?")
            params.append(entity_id)
        if direction in {"in", "both"}:
            clauses.append("dst_id=?")
            params.append(entity_id)
        if not clauses:
            return []
        sql = ("SELECT edge_id,src_id,relation,dst_id,evidence_refs,evidence_kind,trust,"
               "derived_by,first_seen,last_seen,confidence,observation_count,attributes "
               f"FROM graph_edges WHERE ({' OR '.join(clauses)})")
        if relations:
            names = [str(r) for r in relations]
            sql += f" AND relation IN ({','.join('?' * len(names))})"
            params.extend(names)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        return [_edge_row(row) for row in self.conn.execute(sql, params).fetchall()]

    def evidence_for(self, evidence_ref: str) -> dict | None:
        if evidence_ref.startswith("event:"):
            # `event_id != ''` KHÔNG thừa — xem chú thích ở `_resolves()`. Đây
            # là đường "bằng chứng -> event gốc", tức là đúng chỗ người điều
            # tra bấm vào để kiểm chứng một kết luận; 212 ms mỗi lần bấm trên
            # 1,84 triệu dòng, và tăng tuyến tính theo kích thước bảng.
            row = self.conn.execute(
                "SELECT ts,origin,trust,content_hash,source,kind FROM events "
                "WHERE event_id != '' AND event_id=?",
                (evidence_ref.split(":", 1)[1],),
            ).fetchone()
            if row is None:
                return None
            return {"evidence_ref": evidence_ref, "evidence_kind": EvidenceKind.OBSERVED,
                    "ts": row[0], "origin": row[1], "trust": row[2], "content_hash": row[3],
                    "summary": f"{row[4]}/{row[5]}"}
        row = self.conn.execute(
            "SELECT evidence_ref,evidence_kind,ts,origin,trust,content_hash,summary "
            "FROM evidence_objects WHERE evidence_ref=?", (evidence_ref,),
        ).fetchone()
        if row is None:
            return None
        return {"evidence_ref": row[0], "evidence_kind": row[1], "ts": row[2],
                "origin": row[3], "trust": row[4], "content_hash": row[5], "summary": row[6]}

    def orphan_edges(self, limit: int = MAX_LIMIT) -> list[str]:
        """Cạnh trỏ tới bằng chứng không còn tồn tại.

        Gate Phase 1: "Không có orphan evidence reference." Hàm này là cách
        kiểm chứng điều đó trên dữ liệu thật, không phải trên niềm tin.
        """
        found = []
        for edge_id, refs in self.conn.execute(
            "SELECT edge_id,evidence_refs FROM graph_edges LIMIT ?", (int(limit),)
        ).fetchall():
            try:
                items = json.loads(refs)
            except ValueError:
                found.append(edge_id)
                continue
            if any(not self._resolves(ref) for ref in items):
                found.append(edge_id)
        return found

    def counts(self) -> dict:
        return {
            "entities": self.conn.execute("SELECT COUNT(*) FROM graph_entities").fetchone()[0],
            "edges": self.conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0],
            "evidence": self.conn.execute("SELECT COUNT(*) FROM evidence_objects").fetchone()[0],
        }

    def drop_entities_of_type(self, entity_type: str) -> dict:
        """Xoá mọi thực thể một LOẠI, cùng mọi cạnh chạm vào chúng.

        Dùng khi cách dựng `canonical_key` của loại đó đổi: node cũ mang một
        danh tính không còn đúng, và để lẫn với node mới là để hai câu trả lời
        cho cùng một câu hỏi cùng tồn tại.

        `prune()` KHÔNG làm được việc này — nó dọn theo bằng chứng hết hạn, còn
        ở đây bằng chứng vẫn nguyên vẹn, chỉ có danh tính là sai.

        Xoá CẠNH TRƯỚC, trong cùng một giao dịch. `graph_edges` không có ràng
        buộc khoá ngoại (`PRAGMA foreign_key_list` trả về rỗng), nên không có
        gì ngăn cạnh trỏ tới một node đã biến mất ngoài kỷ luật của chính hàm
        này.

        KHÔNG chạm `events`, `evidence_objects`, hay thực thể loại khác. Đồ thị
        dựng lại được từ event; event thì không dựng lại được từ đâu cả.
        """
        with self.conn:
            ids = [row[0] for row in self.conn.execute(
                "SELECT entity_id FROM graph_entities WHERE entity_type=?",
                (str(entity_type),)).fetchall()]
            if not ids:
                return {"entities_removed": 0, "edges_removed": 0}
            edges = 0
            for start in range(0, len(ids), 200):
                batch = ids[start:start + 200]
                marks = ",".join("?" * len(batch))
                edges += self.conn.execute(
                    f"DELETE FROM graph_edges WHERE src_id IN ({marks}) "
                    f"OR dst_id IN ({marks})", batch + batch).rowcount
            removed = self.conn.execute(
                "DELETE FROM graph_entities WHERE entity_type=?",
                (str(entity_type),)).rowcount
        return {"entities_removed": int(removed or 0), "edges_removed": int(edges or 0)}

    def prune(self, older_than_ts: float = 0.0, *, max_edges: int = 0,
              after: str = "") -> dict:
        """Gỡ mọi cạnh không còn bằng chứng, rồi gỡ node treo.

        Gọi SAU khi `Store.maintain()` đã cắt bảng `events` theo hạn lưu trữ.
        Giữ cạnh lại khi bằng chứng đã biến mất tạo ra đúng thứ gate Phase 1
        cấm: một khẳng định không kiểm chứng lại được, trông y hệt một khẳng
        định có bằng chứng.

        `older_than_ts` chỉ áp cho bằng chứng NGOÀI event (alert/intel), thứ
        Shield tự quản hạn; event đã có hạn riêng của bảng `events`.
        """
        removed_evidence = 0
        if older_than_ts:
            removed_evidence = self.conn.execute(
                "DELETE FROM evidence_objects WHERE ts < ?", (older_than_ts,)
            ).rowcount

        # Quét theo LÔ có con trỏ, không quét cả bảng.
        #
        # `.fetchall()` trên toàn bộ `graph_edges` mất 8,6–10,7 giây trên
        # database production (1,24 triệu cạnh, đo được), và cả quãng đó khoá
        # `_ThreadSafeConnection` bị giữ. Watchdog của agent chứng minh store
        # còn sống bằng một lời gọi `get_baseline`, tức nó chờ ĐÚNG cái khoá
        # đó — nên một lượt dọn đủ dài làm systemd giết agent. Đã xảy ra thật:
        # bốn lần SIGABRT rồi service ở trạng thái failed.
        #
        # `max_edges=0` giữ nguyên hành vi cũ (quét hết) cho chỗ gọi nào thật
        # sự cần một lượt đầy đủ.
        #
        # Thứ tự theo `edge_id` (khoá chính) nên con trỏ là ĐỊNH SẴN: lượt sau
        # tiếp đúng chỗ lượt trước dừng, không bỏ sót và không lặp lại. Bỏ dở
        # giữa chừng không làm hỏng gì — một cạnh chưa được xét chỉ đơn giản là
        # chưa tới lượt, y như trước khi lượt dọn này bắt đầu.
        sql = "SELECT edge_id,evidence_refs FROM graph_edges"
        params: tuple = ()
        if after:
            sql += " WHERE edge_id > ?"
            params = (str(after),)
        sql += " ORDER BY edge_id"
        if max_edges > 0:
            sql += " LIMIT ?"
            params = params + (int(max_edges),)

        removed_edges = 0
        scanned = 0
        cursor = after
        for edge_id, refs in self.conn.execute(sql, params).fetchall():
            scanned += 1
            cursor = edge_id
            try:
                items = json.loads(refs)
            except ValueError:
                items = []
            remaining = [ref for ref in items if self._resolves(ref)]
            if not remaining:
                self.conn.execute("DELETE FROM graph_edges WHERE edge_id=?", (edge_id,))
                removed_edges += 1
            elif len(remaining) != len(items):
                self.conn.execute("UPDATE graph_edges SET evidence_refs=? WHERE edge_id=?",
                                  (json.dumps(remaining), edge_id))

        # Hết bảng khi lô này ngắn hơn trần: lượt sau quay lại từ đầu.
        complete = max_edges <= 0 or scanned < max_edges
        # Thực thể không còn cạnh nào là node treo — không nói được điều gì và
        # chỉ làm mọi câu đếm sai.
        #
        # Chỉ chạy khi lô này thực sự gỡ cạnh: phép anti-join mất 1,1 giây trên
        # database production, và chạy nó khi không có gì đổi là trả một giây
        # đó ra để nhận về con số 0.
        removed_entities = 0
        if removed_edges or removed_evidence:
            removed_entities = self.conn.execute(
                "DELETE FROM graph_entities WHERE entity_id NOT IN "
                "(SELECT src_id FROM graph_edges UNION SELECT dst_id FROM graph_edges)"
            ).rowcount
        return {"evidence_removed": removed_evidence, "edges_removed": removed_edges,
                "entities_removed": removed_entities, "edges_scanned": scanned,
                "next_cursor": "" if complete else cursor, "complete": complete}


def _entity_row(row) -> dict:
    return {
        "entity_id": row[0], "entity_type": row[1], "canonical_key": row[2],
        "attributes": json.loads(row[3]), "aliases": json.loads(row[4]),
        "first_seen": row[5], "last_seen": row[6], "trust": row[7],
        "provenance": row[8], "criticality": row[9],
        "resolution_confidence": row[10], "observation_count": row[11],
    }


def _edge_row(row) -> dict:
    return {
        "edge_id": row[0], "src_id": row[1], "relation": row[2], "dst_id": row[3],
        "evidence_refs": json.loads(row[4]), "evidence_kind": row[5], "trust": row[6],
        "derived_by": row[7], "first_seen": row[8], "last_seen": row[9],
        "confidence": row[10], "observation_count": row[11],
        "attributes": json.loads(row[12]),
    }
