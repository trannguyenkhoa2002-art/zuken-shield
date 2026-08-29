"""Hỏi đáp GẮN VÀO MỘT SỰ CỐ — kho và máy trạng thái (Incident Chat v0).

Đây KHÔNG phải trợ lý tổng quát. Mỗi phiên bị buộc vào đúng một `incident_id`,
và ngữ cảnh chỉ dựng từ báo cáo tất định của sự cố đó. Không có đường nào để
hỏi về sự cố khác, về máy khác, hay về bất cứ thứ gì ngoài dữ liệu Shield đã
tự đo được.

Vì sao KHÔNG dùng lại `EnrichmentStore`: danh tính ở đó là `fingerprint`, và
`enqueue` dùng lại BẤT KỲ hàng nào đã có cho khoá đó — bản sửa B1 còn làm điều
đó mạnh hơn có chủ ý. Hai câu hỏi khác nhau về cùng một sự cố và cùng một bằng
chứng sinh ra cùng một fingerprint, nên câu thứ hai sẽ nhận lại câu trả lời của
câu thứ nhất mà không ai biết. Kho này lấy danh tính là TIN NHẮN, không phải
bằng chứng.

Bảng `chat_messages` vừa là hội thoại vừa là hàng đợi: một tin nhắn trợ lý ở
trạng thái `pending` CHÍNH LÀ công việc. Không có bảng job thứ hai, nên không
có cách nào để job và tin nhắn nói hai điều khác nhau.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field

from shield.ai.enrichment import (FAILED, FAILURE_CODES, PENDING, READY, RUNNING,
                                  STALE, STATUSES)

# --- Trần. Một sự cố không được chiếm cả hàng đợi của máy. ---
#
# `MAX_PENDING_PER_SESSION = 1`: model mất ~25 giây một câu. Cho phép xếp hàng
# nhiều câu nghĩa là người dùng gõ năm câu rồi chờ hai phút, và bốn câu đầu đã
# lạc hậu trước khi tới lượt. Một câu một lúc là thành thật với tốc độ thật.
MAX_PENDING_PER_SESSION = 1
MAX_PENDING_CHAT_JOBS = 8
MAX_ATTEMPTS = 2
MAX_SESSION_MESSAGES = 40
MAX_SESSIONS_RETAINED = 50
SESSION_TTL_S = 7 * 86400

# Trần độ dài. Câu hỏi dài hơn thế gần như luôn là dán nhầm cả một file log
# vào, và nó chỉ làm ngân sách token cạn mà không thêm thông tin.
MAX_QUESTION_CHARS = 500
MAX_ANSWER_CHARS = 600

# Số LƯỢT lịch sử đưa lại vào prompt. Một lượt = một hỏi + một đáp.
# Con số cuối chốt theo đo đạc tokenizer thật — xem `docs`/báo cáo phase.
MAX_HISTORY_TURNS = 3

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
ROLES = frozenset({ROLE_USER, ROLE_ASSISTANT})

CHAT_SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_sessions (
    session_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    locale TEXT NOT NULL DEFAULT 'vi',
    -- Dấu vân bằng chứng LÚC MỞ phiên. Bằng chứng đổi thì hội thoại cũ vẫn
    -- đọc được, nhưng câu trả lời MỚI phải dựng trên bằng chứng hiện tại.
    evidence_fingerprint TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    last_active_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    turn_index INTEGER NOT NULL,
    role TEXT NOT NULL,
    -- Câu hỏi của người dùng, đã cắt trần. Câu trả lời chỉ chứa văn bản ĐÃ
    -- QUA `clean_prose` — không bao giờ có output thô của model ở đây.
    question TEXT NOT NULL DEFAULT '',
    -- Ý ĐỊNH đã chốt bằng luật tất định lúc nhận câu hỏi. Lưu lại để lượt chạy
    -- sau không phải đoán lại, và để đo được độ chính xác ánh xạ.
    intent TEXT NOT NULL DEFAULT '',
    answer TEXT NOT NULL DEFAULT '',
    limitations TEXT NOT NULL DEFAULT '',
    ref_ids TEXT NOT NULL DEFAULT '[]',
    -- Dấu vân bằng chứng lúc câu hỏi được đặt. Trả lời xong mà nó đã đổi thì
    -- câu trả lời nói về dữ liệu không còn tồn tại -> `stale`.
    evidence_fingerprint TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    failure_code TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    started_at REAL NOT NULL DEFAULT 0,
    finished_at REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session
    ON chat_messages(session_id, turn_index);
CREATE INDEX IF NOT EXISTS idx_chat_messages_status
    ON chat_messages(status, created_at);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_incident
    ON chat_sessions(incident_id, last_active_at);
"""


@dataclass(frozen=True)
class ChatMessage:
    message_id: str
    session_id: str
    incident_id: str = ""
    turn_index: int = 0
    role: str = ROLE_USER
    question: str = ""
    intent: str = ""
    answer: str = ""
    limitations: str = ""
    ref_ids: tuple = ()
    evidence_fingerprint: str = ""
    status: str = ""
    attempts: int = 0
    failure_code: str = ""
    locale: str = "vi"
    created_at: float = 0.0

    # `job_id` để dùng chung được với `EnrichmentRunner`, thứ chỉ biết
    # `job.job_id`. Không thêm cột: đây là cùng một danh tính, gọi khác tên.
    @property
    def job_id(self) -> str:
        return self.message_id


class ChatStore:
    """Kho HẸP cho hỏi đáp theo sự cố.

    `conn` phải AN TOÀN ĐA LUỒNG — truyền `Store.conn`. Runner gọi kho này từ
    một luồng khác qua `asyncio.to_thread`.
    """

    _SELECT = ("SELECT m.message_id,m.session_id,s.incident_id,m.turn_index,m.role,"
               "m.question,m.answer,m.limitations,m.ref_ids,m.evidence_fingerprint,"
               "m.status,m.attempts,m.failure_code,s.locale,m.created_at,m.intent "
               "FROM chat_messages m JOIN chat_sessions s USING(session_id) ")

    def __init__(self, conn, clock=time.time) -> None:
        self.conn = conn
        self._clock = clock
        self.conn.executescript(CHAT_SCHEMA)

    # --- phiên ---

    def open_session(self, *, incident_id: str, locale: str,
                     evidence_fingerprint: str) -> str:
        """Phiên ĐANG MỞ cho sự cố này, hoặc một phiên mới.

        Một sự cố một phiên: người dùng mở lại màn hình sự cố thì thấy lại đúng
        cuộc hội thoại cũ, không phải một khung trắng.
        """
        now = self._clock()
        row = self.conn.execute(
            "SELECT session_id FROM chat_sessions WHERE incident_id=? "
            "ORDER BY last_active_at DESC LIMIT 1", (str(incident_id),)).fetchone()
        if row:
            with self.conn:
                self.conn.execute(
                    "UPDATE chat_sessions SET last_active_at=?,evidence_fingerprint=? "
                    "WHERE session_id=?", (now, str(evidence_fingerprint), row[0]))
            return row[0]
        session_id = uuid.uuid4().hex
        with self.conn:
            self.conn.execute(
                "INSERT INTO chat_sessions(session_id,incident_id,locale,"
                "evidence_fingerprint,created_at,last_active_at) VALUES(?,?,?,?,?,?)",
                (session_id, str(incident_id), str(locale),
                 str(evidence_fingerprint), now, now))
        return session_id

    def session(self, session_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT session_id,incident_id,locale,evidence_fingerprint,created_at,"
            "last_active_at FROM chat_sessions WHERE session_id=?",
            (str(session_id),)).fetchone()
        if row is None:
            return None
        return {"session_id": row[0], "incident_id": row[1], "locale": row[2],
                "evidence_fingerprint": row[3], "created_at": row[4],
                "last_active_at": row[5]}

    # --- ghi ---

    def ask(self, *, session_id: str, question: str, evidence_fingerprint: str,
            intent: str = "") -> tuple[ChatMessage | None, str]:
        """Ghi câu hỏi + một tin nhắn trợ lý `pending`. -> (tin nhắn, lý do).

        `None` kèm lý do khi bị chặn bởi trần — và đó không phải lỗi, đó là một
        trạng thái người dùng cần đọc được.
        """
        session = self.session(session_id)
        if session is None:
            return None, "unknown_session"
        text = str(question or "").strip()[:MAX_QUESTION_CHARS]
        if not text:
            return None, "empty_question"

        pending = self.conn.execute(
            "SELECT COUNT(*) FROM chat_messages WHERE session_id=? AND status IN (?,?)",
            (str(session_id), PENDING, RUNNING)).fetchone()[0]
        if pending >= MAX_PENDING_PER_SESSION:
            return None, "question_in_flight"
        total = self.conn.execute(
            "SELECT COUNT(*) FROM chat_messages WHERE session_id=?",
            (str(session_id),)).fetchone()[0]
        if total >= MAX_SESSION_MESSAGES:
            return None, "session_full"
        queued = self.conn.execute(
            "SELECT COUNT(*) FROM chat_messages WHERE status IN (?,?)",
            (PENDING, RUNNING)).fetchone()[0]
        if queued >= MAX_PENDING_CHAT_JOBS:
            return None, "queue_full"

        now = self._clock()
        turn = self.conn.execute(
            "SELECT COALESCE(MAX(turn_index),-1)+1 FROM chat_messages WHERE session_id=?",
            (str(session_id),)).fetchone()[0]
        answer_id = uuid.uuid4().hex
        with self.conn:
            self.conn.execute(
                "INSERT INTO chat_messages(message_id,session_id,turn_index,role,"
                "question,evidence_fingerprint,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, str(session_id), turn, ROLE_USER, text,
                 str(evidence_fingerprint), "", now))
            self.conn.execute(
                "INSERT INTO chat_messages(message_id,session_id,turn_index,role,"
                "question,intent,evidence_fingerprint,status,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (answer_id, str(session_id), turn, ROLE_ASSISTANT, text,
                 str(intent), str(evidence_fingerprint), PENDING, now))
            self.conn.execute(
                "UPDATE chat_sessions SET last_active_at=? WHERE session_id=?",
                (now, str(session_id)))
        return self.get(answer_id), "created"

    def answer_now(self, *, session_id: str, question: str, answer: str,
                   evidence_fingerprint: str, intent: str = "",
                   ref_ids=()) -> ChatMessage | None:
        """Câu trả lời TẤT ĐỊNH, không đi qua model.

        Dùng cho câu hỏi ngoài phạm vi và cho yêu cầu hành động: chúng có câu
        trả lời cố định, và gọi model để nói "việc này ngoài phạm vi" là trả 25
        giây cùng một rủi ro bịa đặt để nhận về một câu ta đã biết trước.
        """
        session = self.session(session_id)
        if session is None:
            return None
        text = str(question or "").strip()[:MAX_QUESTION_CHARS]
        now = self._clock()
        turn = self.conn.execute(
            "SELECT COALESCE(MAX(turn_index),-1)+1 FROM chat_messages WHERE session_id=?",
            (str(session_id),)).fetchone()[0]
        answer_id = uuid.uuid4().hex
        with self.conn:
            self.conn.execute(
                "INSERT INTO chat_messages(message_id,session_id,turn_index,role,"
                "question,evidence_fingerprint,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, str(session_id), turn, ROLE_USER, text,
                 str(evidence_fingerprint), "", now))
            self.conn.execute(
                "INSERT INTO chat_messages(message_id,session_id,turn_index,role,"
                "question,intent,answer,ref_ids,evidence_fingerprint,status,"
                "created_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (answer_id, str(session_id), turn, ROLE_ASSISTANT, text,
                 str(intent), str(answer)[:MAX_ANSWER_CHARS],
                 json.dumps([str(r) for r in ref_ids]),
                 str(evidence_fingerprint), READY, now, now))
            self.conn.execute(
                "UPDATE chat_sessions SET last_active_at=? WHERE session_id=?",
                (now, str(session_id)))
        return self.get(answer_id)

    def claim(self) -> ChatMessage | None:
        """Lấy MỘT tin nhắn trợ lý đang chờ. Đồng thời TOÀN CỤC do runner giữ."""
        with self.conn:
            row = self.conn.execute(
                "SELECT message_id FROM chat_messages WHERE status=? "
                "ORDER BY created_at,message_id LIMIT 1", (PENDING,)).fetchone()
            if row is None:
                return None
            self.conn.execute(
                "UPDATE chat_messages SET status=?,started_at=?,attempts=attempts+1 "
                "WHERE message_id=? AND status=?",
                (RUNNING, self._clock(), row[0], PENDING))
        return self.get(row[0])

    def finish_ready(self, message_id: str, payload: dict) -> None:
        """CHỈ văn bản đã qua `clean_prose` và ref do backend gắn."""
        with self.conn:
            self.conn.execute(
                "UPDATE chat_messages SET status=?,answer=?,limitations=?,ref_ids=?,"
                "finished_at=?,failure_code='' WHERE message_id=?",
                (READY, str(payload.get("answer", ""))[:MAX_ANSWER_CHARS],
                 str(payload.get("limitations", ""))[:MAX_ANSWER_CHARS],
                 json.dumps([str(r) for r in payload.get("ref_ids", [])]),
                 self._clock(), str(message_id)))

    def finish_failed(self, message_id: str, failure_code: str) -> None:
        code = failure_code if failure_code in FAILURE_CODES else "internal_error"
        message = self.get(message_id)
        retryable = (message is not None and message.attempts < MAX_ATTEMPTS
                     and code in {"timeout", "resource_limit", "internal_error"})
        with self.conn:
            self.conn.execute(
                "UPDATE chat_messages SET status=?,failure_code=?,finished_at=? "
                "WHERE message_id=?",
                (PENDING if retryable else FAILED, code,
                 0.0 if retryable else self._clock(), str(message_id)))

    def mark_stale(self, message_id: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE chat_messages SET status=?,failure_code=?,finished_at=? "
                "WHERE message_id=?", (STALE, "stale_input", self._clock(),
                                       str(message_id)))

    def reconcile_startup(self) -> dict:
        """`RUNNING` sau khởi động lại là việc của một tiến trình đã chết."""
        with self.conn:
            revived = self.conn.execute(
                "UPDATE chat_messages SET status=?,started_at=0 "
                "WHERE status=? AND attempts < ?",
                (PENDING, RUNNING, MAX_ATTEMPTS)).rowcount
            abandoned = self.conn.execute(
                "UPDATE chat_messages SET status=?,failure_code=?,finished_at=? "
                "WHERE status=? AND attempts >= ?",
                (FAILED, "internal_error", self._clock(), RUNNING,
                 MAX_ATTEMPTS)).rowcount
        return {"revived": revived, "abandoned": abandoned}

    def prune(self, *, ttl_s: float = SESSION_TTL_S,
              max_sessions: int = MAX_SESSIONS_RETAINED) -> int:
        cutoff = self._clock() - ttl_s
        with self.conn:
            old = [r[0] for r in self.conn.execute(
                "SELECT session_id FROM chat_sessions WHERE last_active_at < ?",
                (cutoff,)).fetchall()]
            extra = [r[0] for r in self.conn.execute(
                "SELECT session_id FROM chat_sessions ORDER BY last_active_at DESC "
                "LIMIT -1 OFFSET ?", (int(max_sessions),)).fetchall()]
            removed = 0
            for session_id in set(old) | set(extra):
                self.conn.execute("DELETE FROM chat_messages WHERE session_id=?",
                                  (session_id,))
                removed += self.conn.execute(
                    "DELETE FROM chat_sessions WHERE session_id=?",
                    (session_id,)).rowcount
        return removed

    # --- đọc ---

    def _row(self, row) -> ChatMessage:
        return ChatMessage(
            message_id=row[0], session_id=row[1], incident_id=row[2],
            turn_index=row[3], role=row[4], question=row[5], answer=row[6],
            limitations=row[7], ref_ids=tuple(json.loads(row[8] or "[]")),
            evidence_fingerprint=row[9], status=row[10], attempts=row[11],
            failure_code=row[12], locale=row[13], created_at=row[14],
            intent=row[15])

    def get(self, message_id: str) -> ChatMessage | None:
        row = self.conn.execute(
            self._SELECT + "WHERE m.message_id=?", (str(message_id),)).fetchone()
        return self._row(row) if row else None

    def transcript(self, session_id: str, limit: int = MAX_SESSION_MESSAGES) -> list:
        rows = self.conn.execute(
            self._SELECT + "WHERE m.session_id=? ORDER BY m.turn_index,m.role DESC "
            "LIMIT ?", (str(session_id), int(limit))).fetchall()
        return [self._row(row) for row in rows]

    def history_turns(self, session_id: str, turns: int = MAX_HISTORY_TURNS) -> list:
        """Các lượt ĐÃ TRẢ LỜI AN TOÀN gần nhất, cũ trước.

        Chỉ `READY`: một câu trả lời hỏng hay đang chờ không phải ngữ cảnh, và
        đưa nó vào prompt là dạy model rằng im lặng cũng là một câu trả lời.
        """
        rows = self.conn.execute(
            self._SELECT + "WHERE m.session_id=? AND m.role=? AND m.status=? "
            "AND m.answer<>'' ORDER BY m.turn_index DESC LIMIT ?",
            (str(session_id), ROLE_ASSISTANT, READY, int(turns))).fetchall()
        return [self._row(row) for row in reversed(rows)]

    def counts(self) -> dict:
        return {status: count for status, count in self.conn.execute(
            "SELECT status,COUNT(*) FROM chat_messages WHERE status<>'' "
            "GROUP BY status").fetchall()}

    def oldest_pending(self) -> ChatMessage | None:
        row = self.conn.execute(
            self._SELECT + "WHERE m.status=? ORDER BY m.created_at,m.message_id LIMIT 1",
            (PENDING,)).fetchone()
        return self._row(row) if row else None
