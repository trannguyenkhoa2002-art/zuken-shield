"""Lưu bền lượt điều tra, khẳng định và lời gọi tool (mục 2.3 và mục 7).

Vì sao phải nằm trên đĩa: khi lớp AI nói sai một điều quan trọng, câu hỏi khó
nhất không phải "nó nói gì" mà là **"nó đã nhìn thấy gì lúc nó nói câu đó?"**.
Trả lời được câu đó cần biết nó gọi tool nào, nhận về bao nhiêu dòng, và những
dòng đó trỏ tới bằng chứng nào. Giữ trong bộ nhớ nghĩa là agent khởi động lại
một lần là mất sạch, và lần khởi động lại thường xảy ra ngay sau sự cố.

Hai mức lưu trữ khác nhau, có chủ ý (mục 7: "retention riêng cho raw model
trace và redacted audit"):

- **Vết model** (`model_runs`, `ai_tool_calls`) là dữ liệu vận hành, nhiều và
  nhanh cũ. Hạn ngắn.
- **Kết luận và bằng chứng** (`investigations`, `investigation_hypotheses`,
  `investigation_claims`, `claim_evidence`) là hồ sơ điều tra. Hạn dài.

Mọi thứ ghi vào đây đã đi qua redaction. Bảng này sống lâu hơn kết quả, nên một
bí mật lọt vào đây sẽ ở lại rất lâu.
"""

from __future__ import annotations

import json
import time

from shield.ai.redaction import redact_text

from shield.common.secrets import redact

AI_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    summary_key TEXT NOT NULL DEFAULT '',
    summary_params TEXT NOT NULL DEFAULT '{}',
    started_ts REAL NOT NULL,
    finished_ts REAL NOT NULL DEFAULT 0,
    -- Số liệu để trả lời "lượt này có đáng tin không" mà không phải đọc lại
    -- từng dòng: bao nhiêu khẳng định, bao nhiêu bị hạ cấp, bao nhiêu lần gọi
    -- tool ngoài chính sách.
    claims INTEGER NOT NULL DEFAULT 0,
    downgraded INTEGER NOT NULL DEFAULT 0,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    policy_violations INTEGER NOT NULL DEFAULT 0,
    errors TEXT NOT NULL DEFAULT '[]',
    -- BA GIAI ĐOẠN, không phải một. Khi lớp phân tích nói sai một điều quan
    -- trọng, câu hỏi khó nhất không phải "nó nói gì" mà là "nó đã nói gì
    -- TRƯỚC khi bị sửa" — nếu chỉ lưu bản cuối thì một model đang bịa số liên
    -- tục trông y hệt một model hoàn hảo.
    original_summary TEXT NOT NULL DEFAULT '',
    final_summary TEXT NOT NULL DEFAULT '',
    output_metrics TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS investigation_hypotheses (
    investigation_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unconfirmed',
    confidence_label TEXT NOT NULL DEFAULT 'low',
    downgrade_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(investigation_id, hypothesis_id),
    FOREIGN KEY(investigation_id) REFERENCES investigations(investigation_id)
);

-- Một khẳng định. Hôm nay mỗi giả thuyết sinh đúng một khẳng định, nhưng bảng
-- tách riêng vì `unsupported-claim rate` (mục 3.2) đo THEO KHẲNG ĐỊNH, và một
-- model sau này nêu nhiều khẳng định trong một giả thuyết không được buộc phải
-- đổi schema.
CREATE TABLE IF NOT EXISTS investigation_claims (
    claim_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    statement TEXT NOT NULL DEFAULT '',
    statement_key TEXT NOT NULL DEFAULT '',
    statement_params TEXT NOT NULL DEFAULT '{}',
    supported INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(investigation_id) REFERENCES investigations(investigation_id)
);

CREATE TABLE IF NOT EXISTS claim_evidence (
    claim_id TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    -- supporting | contradicting | missing. Bằng chứng MÂU THUẪN được lưu
    -- ngang hàng với bằng chứng ủng hộ: giấu nó là cách làm một kết luận sai
    -- trông vững chắc.
    role TEXT NOT NULL DEFAULT 'supporting',
    resolved INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(claim_id, evidence_ref, role),
    FOREIGN KEY(claim_id) REFERENCES investigation_claims(claim_id)
);

CREATE TABLE IF NOT EXISTS ai_tool_calls (
    call_id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL DEFAULT '',
    tool TEXT NOT NULL,
    arguments TEXT NOT NULL DEFAULT '{}',
    rows INTEGER NOT NULL DEFAULT 0,
    elapsed_s REAL NOT NULL DEFAULT 0,
    caller TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    ts REAL NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    -- Phase 3B: vòng nào, có thực thi hay bị từ chối. "Bị từ chối" là dòng
    -- đáng đọc nhất của cả bảng — nó là chỗ model thử vượt rào.
    round_index INTEGER NOT NULL DEFAULT -1,
    executed INTEGER NOT NULL DEFAULT 1,
    outcome TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS model_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    started_ts REAL NOT NULL,
    elapsed_s REAL NOT NULL DEFAULT 0,
    ok INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT ''
);
"""

AI_AUDIT_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations(incident_id, started_ts);
CREATE INDEX IF NOT EXISTS idx_investigations_ts ON investigations(started_ts);
CREATE INDEX IF NOT EXISTS idx_claims_investigation ON investigation_claims(investigation_id);
CREATE INDEX IF NOT EXISTS idx_claim_evidence_ref ON claim_evidence(evidence_ref);
CREATE INDEX IF NOT EXISTS idx_ai_tool_calls_ts ON ai_tool_calls(ts);
CREATE INDEX IF NOT EXISTS idx_ai_tool_calls_investigation ON ai_tool_calls(investigation_id, ts);
CREATE INDEX IF NOT EXISTS idx_model_runs_ts ON model_runs(started_ts);
"""

# Hạn lưu trữ mặc định, tính theo ngày. Vết model nhiều và nhanh cũ; hồ sơ điều
# tra thì không.
TRACE_RETENTION_DAYS = 14
INVESTIGATION_RETENTION_DAYS = 180

MAX_TOOL_CALLS_PER_INVESTIGATION = 500


class InvestigationAudit:
    """Ghi và đọc hồ sơ điều tra. Không có phương thức nào SỬA một dòng đã ghi."""

    def __init__(self, conn, clock=time.time) -> None:
        self.conn = conn
        self._clock = clock

    # --- ghi ---

    def record(self, result, *, validation: dict | None = None,
               tool_calls=(), started_ts: float = 0.0,
               original_summary: str = "", final_summary: str = "",
               output_metrics: dict | None = None,
               coordinator: dict | None = None) -> str:
        """Lưu trọn một lượt điều tra. Trả về `investigation_id`.

        Ghi trong MỘT giao dịch: một lượt điều tra được lưu một nửa còn tệ hơn
        không lưu, vì nó trông như một hồ sơ đầy đủ.
        """
        validation = validation or {}
        now = self._clock()
        investigation_id = str(result.investigation_id or f"inv:{int(now * 1000)}")

        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO investigations(investigation_id,incident_id,"
                "provider,model,summary,summary_key,summary_params,started_ts,finished_ts,"
                "claims,downgraded,tool_calls,policy_violations,errors,"
                "original_summary,final_summary,output_metrics) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (investigation_id, str(result.incident_id), str(result.provider),
                 str(result.model), str(result.summary)[:2000], str(result.summary_key),
                 json.dumps(dict(result.summary_params), sort_keys=True, default=str),
                 float(started_ts or now), now,
                 int(validation.get("checked", 0)), int(validation.get("downgraded", 0)),
                 len(tool_calls), int(validation.get("policy_violations", 0)),
                 json.dumps(list(result.errors)),
                 # Bản GỐC vẫn đi qua redaction: giữ được hành vi sai để điều
                 # tra không có nghĩa là giữ luôn bí mật model đã chép vào.
                 redact_text(str(original_summary))[:2000],
                 str(final_summary)[:2000],
                 json.dumps(dict(output_metrics or {}), sort_keys=True)),
            )
            for hypothesis in result.hypotheses:
                self._record_hypothesis(investigation_id, hypothesis)
            for index, call in enumerate(list(tool_calls)[:MAX_TOOL_CALLS_PER_INVESTIGATION]):
                self._record_tool_call(investigation_id, call, index)
            # Bước bị TỪ CHỐI không có mặt trong `tool_calls` — `call_tool` chưa
            # bao giờ được gọi, hoặc đã từ chối trước khi chạy. Chúng phải được
            # ghi, nếu không thì một model liên tục thử vượt rào trông y hệt
            # một model ngoan.
            for index, step in enumerate(list((coordinator or {}).get("steps") or [])):
                if step.get("executed"):
                    continue
                self._record_denied_step(investigation_id, step, index)
        return investigation_id

    def _record_hypothesis(self, investigation_id: str, hypothesis) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO investigation_hypotheses(investigation_id,"
            "hypothesis_id,status,confidence_label,downgrade_reason) VALUES(?,?,?,?,?)",
            (investigation_id, hypothesis.id, hypothesis.status,
             hypothesis.confidence_label, str(hypothesis.downgrade_reason)[:500]),
        )
        claim_id = f"{investigation_id}:{hypothesis.id}"
        self.conn.execute(
            "INSERT OR REPLACE INTO investigation_claims(claim_id,investigation_id,"
            "hypothesis_id,statement,statement_key,statement_params,supported) "
            "VALUES(?,?,?,?,?,?,?)",
            (claim_id, investigation_id, hypothesis.id,
             str(hypothesis.statement)[:1000], str(hypothesis.statement_key),
             json.dumps(dict(hypothesis.statement_params), sort_keys=True, default=str),
             int(hypothesis.status == "supported")),
        )
        self.conn.execute("DELETE FROM claim_evidence WHERE claim_id=?", (claim_id,))
        for role, refs in (("supporting", hypothesis.evidence_refs),
                           ("contradicting", hypothesis.contradicting_evidence_refs),
                           ("missing", hypothesis.missing_evidence_keys)):
            for ref in refs:
                self.conn.execute(
                    "INSERT OR IGNORE INTO claim_evidence(claim_id,evidence_ref,role,"
                    "resolved) VALUES(?,?,?,?)",
                    (claim_id, str(ref)[:200], role, int(role != "missing")),
                )

    def _record_denied_step(self, investigation_id: str, step: dict, index: int) -> None:
        self.conn.execute(
            "INSERT INTO ai_tool_calls(investigation_id,tool,arguments,rows,elapsed_s,"
            "caller,provider,ts,error,round_index,executed,outcome) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (investigation_id, str(step.get("tool", ""))[:64], "{}", 0, 0.0,
             "model", "", self._clock(), "", int(step.get("round", -1)), 0,
             str(step.get("outcome", ""))[:64]),
        )

    def _record_tool_call(self, investigation_id: str, call: dict, index: int) -> None:
        self.conn.execute(
            "INSERT INTO ai_tool_calls(investigation_id,tool,arguments,rows,elapsed_s,"
            "caller,provider,ts,error) VALUES(?,?,?,?,?,?,?,?,?)",
            (investigation_id, str(call.get("tool", ""))[:64],
             # Redaction lần nữa ở đây, dù orchestrator đã che. Bảng này sống
             # lâu hơn nhật ký trong bộ nhớ, nên nó đáng một lần kiểm nữa.
             json.dumps(redact(call.get("arguments") or {}), sort_keys=True, default=str)[:2000],
             int(call.get("rows", 0)), float(call.get("elapsed_s", 0.0)),
             str(call.get("caller", ""))[:64], str(call.get("provider", ""))[:64],
             float(call.get("ts", self._clock())), str(call.get("error", ""))[:500]),
        )

    def record_model_run(self, investigation_id: str, *, provider: str, model: str,
                         started_ts: float, elapsed_s: float, ok: bool,
                         error: str = "") -> None:
        """Một lượt gọi provider. Ghi CẢ lượt hỏng — lượt hỏng mới là lượt cần
        đếm, vì một provider hỏng liên tục là một provider cần tắt."""
        self.conn.execute(
            "INSERT INTO model_runs(investigation_id,provider,model,started_ts,"
            "elapsed_s,ok,error) VALUES(?,?,?,?,?,?,?)",
            (str(investigation_id), str(provider)[:64], str(model)[:64],
             float(started_ts), float(elapsed_s), int(bool(ok)), str(error)[:500]),
        )

    # --- đọc ---

    def get(self, investigation_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT investigation_id,incident_id,provider,model,summary,summary_key,"
            "summary_params,started_ts,finished_ts,claims,downgraded,tool_calls,"
            "policy_violations,errors FROM investigations WHERE investigation_id=?",
            (str(investigation_id),),
        ).fetchone()
        if row is None:
            return None
        return {
            "investigation_id": row[0], "incident_id": row[1], "provider": row[2],
            "model": row[3], "summary": row[4], "summary_key": row[5],
            "summary_params": json.loads(row[6]), "started_ts": row[7],
            "finished_ts": row[8], "claims": row[9], "downgraded": row[10],
            "tool_calls": row[11], "policy_violations": row[12],
            "errors": json.loads(row[13]),
            "hypotheses": self.hypotheses(investigation_id),
        }

    def hypotheses(self, investigation_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT h.hypothesis_id,h.status,h.confidence_label,h.downgrade_reason,"
            "c.claim_id,c.statement,c.statement_key,c.statement_params "
            "FROM investigation_hypotheses h "
            "LEFT JOIN investigation_claims c ON c.investigation_id=h.investigation_id "
            "AND c.hypothesis_id=h.hypothesis_id WHERE h.investigation_id=? "
            "ORDER BY h.hypothesis_id", (str(investigation_id),),
        ).fetchall()
        result = []
        for row in rows:
            evidence = self.claim_evidence(row[4]) if row[4] else {}
            result.append({
                "id": row[0], "status": row[1], "confidence_label": row[2],
                "downgrade_reason": row[3], "statement": row[5] or "",
                "statement_key": row[6] or "",
                "statement_params": json.loads(row[7]) if row[7] else {},
                "evidence_refs": evidence.get("supporting", []),
                "contradicting_evidence_refs": evidence.get("contradicting", []),
                "missing_evidence_keys": evidence.get("missing", []),
            })
        return result

    def claim_evidence(self, claim_id: str) -> dict:
        rows = self.conn.execute(
            "SELECT evidence_ref,role FROM claim_evidence WHERE claim_id=? ORDER BY role",
            (str(claim_id),),
        ).fetchall()
        grouped: dict = {}
        for ref, role in rows:
            grouped.setdefault(role, []).append(ref)
        return grouped

    def for_incident(self, incident_id: str, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT investigation_id FROM investigations WHERE incident_id=? "
            "ORDER BY started_ts DESC LIMIT ?",
            (str(incident_id), max(1, min(int(limit), 100))),
        ).fetchall()
        return [self.get(row[0]) for row in rows]

    def tool_calls(self, investigation_id: str, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT tool,arguments,rows,elapsed_s,caller,provider,ts,error "
            "FROM ai_tool_calls WHERE investigation_id=? ORDER BY call_id LIMIT ?",
            (str(investigation_id), max(1, min(int(limit), 500))),
        ).fetchall()
        return [{"tool": r[0], "arguments": json.loads(r[1]), "rows": r[2],
                 "elapsed_s": r[3], "caller": r[4], "provider": r[5], "ts": r[6],
                 "error": r[7]} for r in rows]

    def unsupported_claim_rate(self, since_ts: float = 0.0) -> float | None:
        """Tỉ lệ khẳng định bị hạ cấp, đo trên dữ liệu ĐÃ LƯU.

        Trước đây con số này chỉ tồn tại trong một lượt chạy. Đo trên dữ liệu
        đã lưu mới trả lời được câu hỏi thật sự đáng hỏi: lớp phân tích này
        đang tốt lên hay tệ đi?
        """
        row = self.conn.execute(
            "SELECT SUM(claims), SUM(downgraded) FROM investigations WHERE started_ts >= ?",
            (float(since_ts),),
        ).fetchone()
        total, downgraded = (row[0] or 0), (row[1] or 0)
        return (downgraded / total) if total else None

    # --- dọn dẹp ---

    def prune(self, *, trace_days: int = TRACE_RETENTION_DAYS,
              investigation_days: int = INVESTIGATION_RETENTION_DAYS) -> dict:
        """Hai hạn lưu trữ khác nhau cho hai loại dữ liệu khác nhau."""
        now = self._clock()
        trace_cutoff = now - max(1, int(trace_days)) * 86400
        record_cutoff = now - max(1, int(investigation_days)) * 86400

        traces = self.conn.execute(
            "DELETE FROM ai_tool_calls WHERE ts < ?", (trace_cutoff,)).rowcount
        runs = self.conn.execute(
            "DELETE FROM model_runs WHERE started_ts < ?", (trace_cutoff,)).rowcount

        stale = [row[0] for row in self.conn.execute(
            "SELECT investigation_id FROM investigations WHERE started_ts < ?",
            (record_cutoff,)).fetchall()]
        for investigation_id in stale:
            # Xoá con trước cha: khoá ngoại sẽ chặn nếu làm ngược, và một lượt
            # dọn dẹp bị chặn giữa chừng để lại đúng thứ nó định dọn.
            self.conn.execute(
                "DELETE FROM claim_evidence WHERE claim_id IN "
                "(SELECT claim_id FROM investigation_claims WHERE investigation_id=?)",
                (investigation_id,))
            self.conn.execute(
                "DELETE FROM investigation_claims WHERE investigation_id=?",
                (investigation_id,))
            self.conn.execute(
                "DELETE FROM investigation_hypotheses WHERE investigation_id=?",
                (investigation_id,))
            self.conn.execute(
                "DELETE FROM investigations WHERE investigation_id=?", (investigation_id,))
        return {"traces_removed": traces + runs, "investigations_removed": len(stale)}
