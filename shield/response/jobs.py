"""Response job bền vững và máy trạng thái (mục 4.1).

Vì sao một job phải nằm trên đĩa chứ không trong bộ nhớ: mọi trạng thái thú vị
đều là trạng thái agent có thể chết ở giữa. Áp luật firewall xong rồi chết
trước khi ghi "đã áp" nghĩa là lần khởi động sau không ai biết máy đang bị cách
ly. Đó không phải giả thuyết — nó đã xảy ra ở Batch 2.0-P0 và phải sửa bằng một
lượt đối chiếu với kernel lúc khởi động.

Ba tính chất bắt buộc của mọi chuyển trạng thái:

1. **Giao dịch.** Ghi trạng thái mới và ghi dòng lịch sử phải cùng thành công
   hoặc cùng thất bại. Nửa vời nghĩa là lịch sử nói một đằng, trạng thái nói
   một nẻo, và không ai biết bên nào đúng.
2. **Chỉ thêm.** Lịch sử không bao giờ bị sửa hay xoá. Một dòng chuyển trạng
   thái sai vẫn phải nằm đó — nó là bằng chứng.
3. **Idempotent.** Cùng một lệnh gửi hai lần không được tạo hai hành động.
   Mạng chập, người bấm hai lần, tiến trình thử lại — cả ba đều xảy ra thật.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field


class JobState:
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    APPLYING = "APPLYING"
    APPLIED = "APPLIED"
    APPLY_FAILED = "APPLY_FAILED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    VERIFY_FAILED = "VERIFY_FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"

    ALL = frozenset({
        PROPOSED, APPROVED, DENIED, EXPIRED, APPLYING, APPLIED, APPLY_FAILED,
        VERIFYING, VERIFIED, VERIFY_FAILED, ROLLING_BACK, ROLLED_BACK, ROLLBACK_FAILED,
    })


# Máy trạng thái, chép đúng từ mục 4.1 của kế hoạch. Tập ĐÓNG: một chuyển
# trạng thái không có trong bảng này bị từ chối, chứ không được "thử xem sao".
TRANSITIONS: dict[str, frozenset[str]] = {
    JobState.PROPOSED: frozenset({JobState.APPROVED, JobState.DENIED, JobState.EXPIRED}),
    JobState.APPROVED: frozenset({JobState.APPLYING, JobState.EXPIRED}),
    JobState.APPLYING: frozenset({JobState.APPLIED, JobState.APPLY_FAILED,
                                  JobState.ROLLING_BACK}),
    JobState.APPLIED: frozenset({JobState.VERIFYING, JobState.ROLLING_BACK}),
    JobState.VERIFYING: frozenset({JobState.VERIFIED, JobState.VERIFY_FAILED,
                                   JobState.ROLLING_BACK}),
    # VERIFIED không phải trạng thái cuối: một hành động có TTL vẫn phải được
    # gỡ khi hết hạn, và đường gỡ đó đi qua ROLLING_BACK.
    JobState.VERIFIED: frozenset({JobState.ROLLING_BACK}),
    JobState.VERIFY_FAILED: frozenset({JobState.ROLLING_BACK}),
    JobState.APPLY_FAILED: frozenset({JobState.ROLLING_BACK}),
    JobState.ROLLING_BACK: frozenset({JobState.ROLLED_BACK, JobState.ROLLBACK_FAILED}),
    # ROLLBACK_FAILED có thể thử lại. Trạng thái cuối duy nhất cho nó là thành
    # công — bỏ cuộc ở đây nghĩa là để lại một luật firewall không ai gỡ.
    JobState.ROLLBACK_FAILED: frozenset({JobState.ROLLING_BACK}),
    JobState.ROLLED_BACK: frozenset(),
    JobState.DENIED: frozenset(),
    JobState.EXPIRED: frozenset(),
}

TERMINAL = frozenset({JobState.DENIED, JobState.EXPIRED, JobState.ROLLED_BACK})

# Trạng thái mà agent chết ở đó sẽ để lại việc dang dở trên hệ thống thật.
# Lần khởi động sau PHẢI xử lý chúng, không được bỏ qua.
UNFINISHED = frozenset({
    JobState.APPLYING, JobState.APPLIED, JobState.VERIFYING, JobState.ROLLING_BACK,
})

RESPONSE_SCHEMA = """
CREATE TABLE IF NOT EXISTS response_jobs (
    job_id TEXT PRIMARY KEY,
    -- Khoá chống trùng: cùng một quyết định gửi hai lần cho ra cùng khoá này,
    -- và UNIQUE ở tầng database là thứ duy nhất chống được hai tiến trình
    -- cùng gửi đồng thời. Kiểm bằng SELECT trước INSERT thì vẫn có khe hở.
    idempotency_key TEXT NOT NULL UNIQUE,
    decision_id TEXT NOT NULL DEFAULT '',
    incident_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    ttl_s INTEGER NOT NULL DEFAULT 0,
    requires_human INTEGER NOT NULL DEFAULT 1,
    apply_result TEXT NOT NULL DEFAULT '{}',
    verify_result TEXT NOT NULL DEFAULT '{}',
    rollback_result TEXT NOT NULL DEFAULT '{}',
    created_ts REAL NOT NULL,
    updated_ts REAL NOT NULL,
    expires_ts REAL NOT NULL DEFAULT 0
);

-- CHỈ THÊM. Không có UPDATE hay DELETE nào chạm vào bảng này ở bất cứ đâu
-- trong mã nguồn, và có test đọc AST khẳng định điều đó.
CREATE TABLE IF NOT EXISTS response_transitions (
    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    ts REAL NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(job_id) REFERENCES response_jobs(job_id)
);

CREATE TABLE IF NOT EXISTS verification_results (
    verification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    ts REAL NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    -- Bằng chứng ĐỌC TỪ HỆ THỐNG, không phải thông điệp của executor.
    observed TEXT NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(job_id) REFERENCES response_jobs(job_id)
);
"""

RESPONSE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_response_jobs_state ON response_jobs(state, updated_ts);
CREATE INDEX IF NOT EXISTS idx_response_jobs_expiry ON response_jobs(expires_ts);
-- `incident_response_jobs()` tra theo cột này. Không có index thì đó là một
-- lần quét toàn bảng cho mỗi lần mở incident — đúng loại lỗi đã đốt trọn
-- một nhân CPU ở 2.0 và làm cả máy chậm 10 lần.
CREATE INDEX IF NOT EXISTS idx_response_jobs_incident ON response_jobs(incident_id);
CREATE INDEX IF NOT EXISTS idx_response_transitions_job ON response_transitions(job_id, ts);
CREATE INDEX IF NOT EXISTS idx_verification_job ON verification_results(job_id, ts);
"""


class TransitionError(RuntimeError):
    """Chuyển trạng thái không hợp lệ. Không bao giờ được nuốt."""


def next_states(state: str) -> frozenset[str]:
    return TRANSITIONS.get(state, frozenset())


def is_terminal(state: str) -> bool:
    return state in TERMINAL


@dataclass(frozen=True)
class ResponseJob:
    job_id: str
    idempotency_key: str
    action: str
    target: dict
    state: str
    decision_id: str = ""
    incident_id: str = ""
    evidence_refs: tuple[str, ...] = ()
    ttl_s: int = 0
    requires_human: bool = True
    apply_result: dict = field(default_factory=dict)
    verify_result: dict = field(default_factory=dict)
    rollback_result: dict = field(default_factory=dict)
    created_ts: float = 0.0
    updated_ts: float = 0.0
    expires_ts: float = 0.0

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id, "idempotency_key": self.idempotency_key,
            "decision_id": self.decision_id, "incident_id": self.incident_id,
            "action": self.action, "target": dict(self.target), "state": self.state,
            "evidence_refs": list(self.evidence_refs), "ttl_s": self.ttl_s,
            "requires_human": self.requires_human,
            "apply_result": dict(self.apply_result),
            "verify_result": dict(self.verify_result),
            "rollback_result": dict(self.rollback_result),
            "created_ts": self.created_ts, "updated_ts": self.updated_ts,
            "expires_ts": self.expires_ts,
        }


def _row_to_job(row) -> ResponseJob:
    return ResponseJob(
        job_id=row[0], idempotency_key=row[1], decision_id=row[2], incident_id=row[3],
        action=row[4], target=json.loads(row[5]), state=row[6],
        evidence_refs=tuple(json.loads(row[7])), ttl_s=row[8],
        requires_human=bool(row[9]), apply_result=json.loads(row[10]),
        verify_result=json.loads(row[11]), rollback_result=json.loads(row[12]),
        created_ts=row[13], updated_ts=row[14], expires_ts=row[15],
    )


_COLUMNS = ("job_id,idempotency_key,decision_id,incident_id,action,target,state,"
            "evidence_refs,ttl_s,requires_human,apply_result,verify_result,"
            "rollback_result,created_ts,updated_ts,expires_ts")


class ResponseJobStore:
    """Lưu trữ job. Mọi chuyển trạng thái đi qua đây và chỉ qua đây."""

    def __init__(self, conn, clock=time.time) -> None:
        self.conn = conn
        self._clock = clock

    # --- tạo ---

    def create(self, *, idempotency_key: str, action: str, target: dict,
               decision_id: str = "", incident_id: str = "", evidence_refs=(),
               ttl_s: int = 0, requires_human: bool = True) -> tuple[ResponseJob, bool]:
        """Tạo một job, hoặc trả về job đã có cùng khoá chống trùng.

        Trả `(job, đã_tạo_mới)`. Gửi lại cùng một lệnh KHÔNG tạo job thứ hai —
        đây là chỗ chặn "bấm hai lần thì chặn IP hai lần".
        """
        if not idempotency_key:
            raise ValueError("job phải có khoá chống trùng")
        existing = self.by_idempotency_key(idempotency_key)
        if existing is not None:
            return existing, False

        now = self._clock()
        job = ResponseJob(
            job_id="job:" + uuid.uuid4().hex,
            idempotency_key=str(idempotency_key),
            decision_id=str(decision_id), incident_id=str(incident_id),
            action=str(action), target=dict(target), state=JobState.PROPOSED,
            evidence_refs=tuple(str(ref) for ref in evidence_refs),
            ttl_s=int(ttl_s), requires_human=bool(requires_human),
            created_ts=now, updated_ts=now,
        )
        try:
            self.conn.execute(
                f"INSERT INTO response_jobs({_COLUMNS}) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job.job_id, job.idempotency_key, job.decision_id, job.incident_id,
                 job.action, json.dumps(job.target, sort_keys=True), job.state,
                 json.dumps(list(job.evidence_refs)), job.ttl_s, int(job.requires_human),
                 "{}", "{}", "{}", job.created_ts, job.updated_ts, 0.0),
            )
        except Exception:
            # UNIQUE ở tầng database là lưới cuối: hai tiến trình cùng gọi
            # `create` sẽ cùng thấy `by_idempotency_key` trả None rồi cùng
            # INSERT. Một bên thua, và bên thua phải nhận job của bên thắng chứ
            # không được ném lỗi lên người dùng.
            duplicate = self.by_idempotency_key(idempotency_key)
            if duplicate is not None:
                return duplicate, False
            raise
        self._record_transition(job.job_id, "", JobState.PROPOSED, "system", "job created")
        return job, True

    # --- đọc ---

    def get(self, job_id: str) -> ResponseJob | None:
        row = self.conn.execute(
            f"SELECT {_COLUMNS} FROM response_jobs WHERE job_id=?", (str(job_id),)
        ).fetchone()
        return _row_to_job(row) if row else None

    def by_idempotency_key(self, key: str) -> ResponseJob | None:
        row = self.conn.execute(
            f"SELECT {_COLUMNS} FROM response_jobs WHERE idempotency_key=?", (str(key),)
        ).fetchone()
        return _row_to_job(row) if row else None

    def list_jobs(self, state: str | None = None, limit: int = 200) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        if state:
            rows = self.conn.execute(
                f"SELECT {_COLUMNS} FROM response_jobs WHERE state=? "
                "ORDER BY updated_ts DESC LIMIT ?", (str(state), limit)).fetchall()
        else:
            rows = self.conn.execute(
                f"SELECT {_COLUMNS} FROM response_jobs ORDER BY updated_ts DESC LIMIT ?",
                (limit,)).fetchall()
        return [_row_to_job(row).to_dict() for row in rows]

    def transitions(self, job_id: str, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT from_state,to_state,ts,actor,detail FROM response_transitions "
            "WHERE job_id=? ORDER BY transition_id ASC LIMIT ?",
            (str(job_id), max(1, min(int(limit), 500))),
        ).fetchall()
        return [{"from_state": r[0], "to_state": r[1], "ts": r[2],
                 "actor": r[3], "detail": r[4]} for r in rows]

    def verifications(self, job_id: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts,verified,observed,reason FROM verification_results "
            "WHERE job_id=? ORDER BY verification_id ASC LIMIT ?",
            (str(job_id), max(1, min(int(limit), 200))),
        ).fetchall()
        results = []
        for r in rows:
            observed = json.loads(r[2])
            results.append({
                "ts": r[0], "verified": bool(r[1]), "reason": r[3],
                "reason_key": observed.pop("_reason_key", ""),
                "reason_params": observed.pop("_reason_params", {}),
                "observed": observed,
            })
        return results

    def unfinished(self, limit: int = 200) -> list[ResponseJob]:
        """Job đang dang dở trên hệ thống thật khi agent chết.

        Đây là danh sách lần khởi động sau PHẢI xử lý. Bỏ qua nó nghĩa là để
        lại một luật firewall không ai gỡ.
        """
        placeholders = ",".join("?" * len(UNFINISHED))
        rows = self.conn.execute(
            f"SELECT {_COLUMNS} FROM response_jobs WHERE state IN ({placeholders}) "
            "ORDER BY updated_ts ASC LIMIT ?",
            (*sorted(UNFINISHED), max(1, min(int(limit), 500))),
        ).fetchall()
        return [_row_to_job(row) for row in rows]

    def expired(self, at: float | None = None, limit: int = 200) -> list[ResponseJob]:
        """Job đã quá TTL và cần được gỡ."""
        now = self._clock() if at is None else at
        rows = self.conn.execute(
            f"SELECT {_COLUMNS} FROM response_jobs WHERE expires_ts > 0 AND expires_ts <= ? "
            "AND state IN (?,?) ORDER BY expires_ts ASC LIMIT ?",
            (now, JobState.VERIFIED, JobState.APPLIED, max(1, min(int(limit), 500))),
        ).fetchall()
        return [_row_to_job(row) for row in rows]

    # --- chuyển trạng thái ---

    def transition(self, job_id: str, to_state: str, *, actor: str = "system",
                   detail: str = "", **results) -> ResponseJob:
        """Chuyển trạng thái trong MỘT giao dịch, kèm dòng lịch sử.

        Ghi trạng thái mới và ghi lịch sử phải cùng thành công hoặc cùng thất
        bại. Nửa vời nghĩa là lịch sử nói một đằng, trạng thái nói một nẻo, và
        không ai biết bên nào đúng.
        """
        if to_state not in JobState.ALL:
            raise TransitionError(f"trạng thái không tồn tại: {to_state!r}")
        job = self.get(job_id)
        if job is None:
            raise TransitionError(f"không có job {job_id!r}")
        if to_state == job.state:
            # Lặp lại đúng trạng thái hiện tại là no-op, không phải lỗi: một
            # lượt thử lại sau khi mất kết nối sẽ làm đúng chuyện này.
            return job
        if to_state not in next_states(job.state):
            raise TransitionError(
                f"không được đi từ {job.state} sang {to_state}; "
                f"chỉ có thể: {sorted(next_states(job.state)) or 'không gì cả (trạng thái cuối)'}")

        now = self._clock()
        expires = job.expires_ts
        if to_state == JobState.APPLIED and job.ttl_s > 0:
            # Hạn gỡ tính TỪ LÚC ÁP THÀNH CÔNG, không phải từ lúc đề xuất. Một
            # job nằm chờ người duyệt ba tiếng không được coi là đã hết hạn
            # ngay khi vừa áp.
            expires = now + job.ttl_s
        if to_state in {JobState.ROLLED_BACK, JobState.DENIED, JobState.EXPIRED}:
            expires = 0.0

        fields = {"apply_result": job.apply_result, "verify_result": job.verify_result,
                  "rollback_result": job.rollback_result}
        for name in fields:
            if name in results and results[name] is not None:
                fields[name] = dict(results[name])

        with self.conn:
            self.conn.execute(
                "UPDATE response_jobs SET state=?,updated_ts=?,expires_ts=?,"
                "apply_result=?,verify_result=?,rollback_result=? WHERE job_id=? AND state=?",
                (to_state, now, expires,
                 json.dumps(fields["apply_result"], sort_keys=True, default=str),
                 json.dumps(fields["verify_result"], sort_keys=True, default=str),
                 json.dumps(fields["rollback_result"], sort_keys=True, default=str),
                 job.job_id, job.state),
            )
            self._record_transition(job.job_id, job.state, to_state, actor, detail)
        updated = self.get(job_id)
        assert updated is not None
        return updated

    def _record_transition(self, job_id: str, from_state: str, to_state: str,
                           actor: str, detail: str) -> None:
        self.conn.execute(
            "INSERT INTO response_transitions(job_id,from_state,to_state,ts,actor,detail) "
            "VALUES(?,?,?,?,?,?)",
            (job_id, from_state, to_state, self._clock(), str(actor)[:64], str(detail)[:500]),
        )

    def record_verification(self, job_id: str, *, verified: bool, observed: dict,
                            reason: str = "", reason_key: str = "",
                            reason_params: dict | None = None) -> None:
        """Ghi bằng chứng hậu kiểm. Chỉ thêm, không bao giờ sửa.

        `observed` là thứ ĐỌC TỪ HỆ THỐNG. Nếu nó rỗng thì không có kiểm chứng
        nào diễn ra, và một job "VERIFIED" với `observed` rỗng là một job nói dối.
        """
        # Khoá dịch đi CÙNG bằng chứng, không tách ra: một bản ghi hậu kiểm
        # đọc lại sáu tháng sau vẫn phải hiển thị được bằng ngôn ngữ người đọc
        # chọn lúc đó, chứ không phải ngôn ngữ agent dùng lúc ghi.
        self.conn.execute(
            "INSERT INTO verification_results(job_id,ts,verified,observed,reason) "
            "VALUES(?,?,?,?,?)",
            (str(job_id), self._clock(), int(bool(verified)),
             json.dumps({**observed, "_reason_key": reason_key,
                         "_reason_params": reason_params or {}},
                        sort_keys=True, default=str),
             str(reason)[:500]),
        )
