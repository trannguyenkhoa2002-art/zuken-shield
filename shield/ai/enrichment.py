"""Công việc LÀM GIÀU báo cáo bằng văn xuôi model (Phase 3D rollout).

Bài toán: suy luận mất ~15 giây, còn báo cáo tất định mất 0,1 giây. Ghép hai
thứ vào một lời gọi nghĩa là người dùng chờ 15 giây cho một thứ đã sẵn sàng
ngay từ đầu — và khi model hỏng, họ chờ 15 giây rồi không nhận được gì.

Nên tách: **báo cáo tất định trả về NGAY, văn xuôi tới sau nếu tới.**

Vì sao một kho riêng, rất hẹp, thay vì dùng lại `ResponseJobStore`: job phản
ứng có rollback, có xác minh, có dead-man switch, và một job thất bại ở đó
nghĩa là hệ thống đang ở trạng thái không rõ. Job làm giàu thì thất bại là
chuyện thường và hậu quả bằng không — báo cáo vẫn đầy đủ. Hai vòng đời khác
nhau dùng chung một bảng nghĩa là ngữ nghĩa của bảng đó không còn là gì cả.

Bất biến trung tâm: **không bao giờ phục vụ văn xuôi cũ.** Bằng chứng đổi,
ngôn ngữ đổi, model đổi, prompt đổi — mỗi thứ đều làm khoá đổi, và khoá cũ
không bao giờ khớp lại. Một đoạn giải thích đúng cho dữ liệu của hôm qua là
một đoạn SAI cho dữ liệu hôm nay, và nó không tự nói ra điều đó.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
import uuid

# Phiên bản HỢP ĐỒNG giải thích. Tăng khi hình dạng ô, luật prompt, hay bộ kiểm
# đầu ra đổi — mọi văn xuôi sinh bởi bản cũ phải mất hiệu lực.
CONTRACT_VERSION = 1

# Dấu vân của những artefact QUYẾT ĐỊNH hình dạng đầu ra: ngữ pháp, khối chỉ
# dẫn trong prompt, và hợp đồng ba ô.
#
# Một hằng số tăng bằng tay là một hằng số có người quên tăng — và quên ở đây
# nghĩa là văn xuôi sinh bởi prompt cũ vẫn được phục vụ như thể nó còn đúng.
# Nên có một bài test băm ba artefact đó và so với hằng số dưới đây: đổi prompt
# mà không tăng `CONTRACT_VERSION` sẽ làm bộ test đỏ, kèm digest mới để dán vào.
#
# Đây KHÔNG phải một hệ thống phiên bản; nó là một sợi dây buộc hai thứ đáng lẽ
# phải đi cùng nhau.
CONTRACT_DIGEST = "5a7ca3352071eac2"


def contract_digest() -> str:
    """Băm ngữ pháp + chỉ dẫn prompt + hợp đồng ô. Dùng cho test ghim."""
    import hashlib

    from shield.ai.worker.prompt import _EXPLAIN
    from shield.ai.worker.runtime import explanation_grammar
    from shield.report.template import AI_SLOTS, MAX_SLOT_CHARS

    digest = hashlib.sha256()
    digest.update(explanation_grammar().encode("utf-8"))
    digest.update(_EXPLAIN.encode("utf-8"))
    digest.update(repr((tuple(AI_SLOTS), MAX_SLOT_CHARS)).encode("utf-8"))
    return digest.hexdigest()[:16]

# Trạng thái ĐÓNG. Không có "đang xử lý một phần", không có chuỗi tự do.
PENDING = "pending"
RUNNING = "running"
READY = "ready"
FAILED = "failed"
STALE = "stale"
STATUSES = frozenset({PENDING, RUNNING, READY, FAILED, STALE})

# Trạng thái báo cho client, ĐÓNG. Khác `STATUSES`: đây là thứ người đọc thấy.
CLIENT_DISABLED = "disabled"
CLIENT_INELIGIBLE = "ineligible"
CLIENT_PENDING = "pending"
CLIENT_READY = "ready"
CLIENT_FAILED = "failed"
CLIENT_DEFERRED = "deferred"
CLIENT_STATUSES = frozenset({CLIENT_DISABLED, CLIENT_INELIGIBLE, CLIENT_PENDING,
                             CLIENT_READY, CLIENT_FAILED, CLIENT_DEFERRED})

# Mã hỏng ĐÓNG. Không câu ngoại lệ thô nào lọt ra: thông điệp ngoại lệ do mã
# model sinh và có thể chứa bất cứ thứ gì.
FAILURE_CODES = frozenset({
    "provider_unavailable", "timeout", "resource_limit", "malformed_output",
    "validation_failed", "kill_switch", "stale_input", "queue_full",
    "internal_error",
})

# Trần. Hàng đợi đầy KHÔNG được chặn sản phẩm — báo cáo tất định vẫn trả bình
# thường, chỉ là không kèm văn xuôi.
MAX_QUEUED = 16
MAX_CONCURRENT = 1
MAX_ATTEMPTS = 2
# Job `running` quá hạn này coi như chết cùng tiến trình trước.
STALE_RUNNING_S = 600.0
# Giữ job đã xong bao lâu. Ngắn: văn xuôi mất hiệu lực khi bằng chứng đổi, nên
# một hàng cũ gần như luôn là hàng không dùng được.
COMPLETED_RETENTION_S = 7 * 86400

ENRICHMENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_enrichment_jobs (
    job_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    -- Khoá đồng nhất. Gồm bằng chứng, ngôn ngữ, provider, model và phiên bản
    -- hợp đồng — đổi bất kỳ thứ nào là một job KHÁC, không phải job cũ.
    fingerprint TEXT NOT NULL,
    locale TEXT NOT NULL DEFAULT 'vi',
    provider TEXT NOT NULL DEFAULT '',
    model_version TEXT NOT NULL DEFAULT '',
    contract_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    failure_code TEXT NOT NULL DEFAULT '',
    -- CHỈ ba ô văn xuôi ĐÃ QUA kiểm và che bí mật. Không output thô: bản thô
    -- đã có `InvestigationAudit` giữ, và giữ hai bản là mở hai chỗ để rò.
    slots TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    started_at REAL NOT NULL DEFAULT 0,
    finished_at REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_enrichment_fingerprint
    ON ai_enrichment_jobs(fingerprint, status);
CREATE INDEX IF NOT EXISTS idx_enrichment_incident
    ON ai_enrichment_jobs(incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_enrichment_status
    ON ai_enrichment_jobs(status, created_at);
"""


def fingerprint(*, incident_id: str, evidence: dict, locale: str, provider: str,
                model_version: str, contract_version: int = CONTRACT_VERSION) -> str:
    """Khoá đồng nhất của một lượt giải thích.

    Mọi thứ ảnh hưởng tới ĐẦU RA đều nằm trong khoá. Thiếu một thành phần nghĩa
    là có một cách để dữ liệu đổi mà khoá không đổi — và khi đó Shield sẽ phục
    vụ một đoạn giải thích đúng cho dữ liệu của hôm qua.
    """
    payload = json.dumps({
        "incident": str(incident_id),
        "evidence": evidence,
        "locale": str(locale),
        "provider": str(provider),
        "model": str(model_version),
        "contract": int(contract_version),
    }, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def model_version(config) -> str:
    """Định danh model + cấu hình ảnh hưởng tới đầu ra.

    KHÔNG băm cả file model: nó hơn 1 GiB và phải băm lại mỗi lượt. Đường dẫn
    cộng kích thước cộng thời điểm sửa đủ để phát hiện một file bị thay — và
    nếu ai đó thay file mà giữ nguyên cả ba thứ đó thì họ đã có quyền làm
    những việc tệ hơn nhiều.
    """
    import os

    parts = {"runtime": getattr(config, "runtime", ""),
             "path": getattr(config, "model_path", ""),
             "mode": getattr(config, "mode", ""),
             "ctx": getattr(config, "context_tokens", 0),
             "max_tokens": getattr(config, "max_output_tokens", 0),
             "temperature": getattr(config, "temperature", 0.0),
             "seed": getattr(config, "seed", 0)}
    try:
        info = os.stat(str(config.model_path))
        parts["size"] = info.st_size
        parts["mtime"] = int(info.st_mtime)
    except (OSError, AttributeError, TypeError):
        parts["size"] = parts["mtime"] = 0
    blob = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclasses.dataclass(frozen=True)
class EnrichmentJob:
    job_id: str
    incident_id: str
    fingerprint: str
    locale: str
    provider: str
    model_version: str
    contract_version: int
    status: str
    attempts: int
    failure_code: str
    slots: dict
    created_at: float
    started_at: float
    finished_at: float

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data["slots"] = dict(self.slots)
        return data


class EnrichmentStore:
    """Kho HẸP cho job làm giàu. Không dùng lại `ResponseJobStore`.

    Không có phương thức nào sửa `fingerprint` của một hàng: khoá là danh tính,
    và một danh tính sửa được là một danh tính không dùng để so được.

    `conn` phải AN TOÀN ĐA LUỒNG — truyền `Store.conn`, thứ đã bọc sẵn RLock và
    mở với `check_same_thread=False`. Runner gọi kho này từ một luồng khác qua
    `asyncio.to_thread`, và một connection sqlite trần sẽ ném
    `ProgrammingError` ở đúng chỗ đó.
    """

    def __init__(self, conn, clock=time.time) -> None:
        self.conn = conn
        self._clock = clock
        self.conn.executescript(ENRICHMENT_SCHEMA)

    # --- ghi ---

    def enqueue(self, *, incident_id: str, fingerprint_value: str, locale: str,
                provider: str, model_version_value: str,
                contract_version: int = CONTRACT_VERSION,
                max_queued: int = MAX_QUEUED) -> tuple[EnrichmentJob | None, str]:
        """-> (job, lý do). Job đã có cùng khoá thì DÙNG LẠI, không tạo thêm.

        Trả về `None` khi hàng đợi đầy — và đó KHÔNG phải lỗi: báo cáo tất định
        vẫn ra bình thường, chỉ là không kèm văn xuôi.
        """
        now = self._clock()
        existing = self.by_fingerprint(fingerprint_value)
        if existing is not None:
            # MỌI trạng thái đều dùng lại, kể cả `FAILED`/`STALE`.
            #
            # Trước đây chỉ `PENDING/RUNNING/READY` được dùng lại, nên một hàng
            # `FAILED` bị bỏ qua và lượt mở lại kế tiếp đúc một hàng MỚI với
            # `attempts=0`. Hậu quả có hai phần, và cả hai đều đã đo được:
            # `MAX_ATTEMPTS` chỉ còn ràng buộc trong phạm vi một hàng nên số
            # lượt suy luận cho cùng một khoá là vô hạn; và giao diện không bao
            # giờ hiện `failed`, vì `_attach_enrichment` xếp hàng TRƯỚC khi đọc
            # trạng thái nên nó luôn đọc đúng cái hàng vừa tạo.
            #
            # Khoá là danh tính. Cùng một khoá nghĩa là cùng một câu hỏi trên
            # cùng một dữ liệu, và câu hỏi đó đã được trả lời — kể cả khi câu
            # trả lời là "hỏng". Muốn hỏi lại thì phải có gì đó thật sự đổi, và
            # khi đó khoá tự đổi theo: bằng chứng, locale, provider, model/cấu
            # hình, hay `CONTRACT_VERSION` đều nằm trong khoá. Một admin sửa
            # cấu hình model sẽ có khoá mới mà không cần ai bấm "thử lại".
            #
            # Lượt thử thứ hai cho mã hỏng tạm thời KHÔNG mất: `finish_failed`
            # đưa chính hàng này về `PENDING` khi `attempts < MAX_ATTEMPTS`.
            # Không cần cooldown, không cần scheduler.
            return existing, "reused"
        queued = self.conn.execute(
            "SELECT COUNT(*) FROM ai_enrichment_jobs WHERE status IN (?,?)",
            (PENDING, RUNNING)).fetchone()[0]
        if queued >= max_queued:
            return None, "queue_full"
        job = EnrichmentJob(
            job_id=uuid.uuid4().hex, incident_id=str(incident_id),
            fingerprint=str(fingerprint_value), locale=str(locale),
            provider=str(provider), model_version=str(model_version_value),
            contract_version=int(contract_version), status=PENDING, attempts=0,
            failure_code="", slots={}, created_at=now, started_at=0.0, finished_at=0.0)
        with self.conn:
            self.conn.execute(
                "INSERT INTO ai_enrichment_jobs(job_id,incident_id,fingerprint,locale,"
                "provider,model_version,contract_version,status,attempts,failure_code,"
                "slots,created_at,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job.job_id, job.incident_id, job.fingerprint, job.locale, job.provider,
                 job.model_version, job.contract_version, job.status, job.attempts,
                 job.failure_code, "{}", job.created_at, 0.0, 0.0))
        return job, "created"

    def claim(self) -> EnrichmentJob | None:
        """Lấy MỘT job đang chờ và đánh dấu đang chạy. `MAX_CONCURRENT = 1`."""
        with self.conn:
            running = self.conn.execute(
                "SELECT COUNT(*) FROM ai_enrichment_jobs WHERE status=?",
                (RUNNING,)).fetchone()[0]
            if running >= MAX_CONCURRENT:
                return None
            row = self.conn.execute(
                "SELECT job_id FROM ai_enrichment_jobs WHERE status=? "
                "ORDER BY created_at LIMIT 1", (PENDING,)).fetchone()
            if row is None:
                return None
            now = self._clock()
            self.conn.execute(
                "UPDATE ai_enrichment_jobs SET status=?,started_at=?,attempts=attempts+1 "
                "WHERE job_id=? AND status=?", (RUNNING, now, row[0], PENDING))
        return self.get(row[0])

    def finish_ready(self, job_id: str, slots: dict) -> None:
        """Chỉ ba ô ĐÃ KIỂM được lưu. Trường lạ bị bỏ, không bị lưu 'phòng khi'."""
        safe = {name: str(slots.get(name, "") or "")[:600]
                for name in ("analysis", "hypothesis_rationale", "why_this_matters")}
        with self.conn:
            self.conn.execute(
                "UPDATE ai_enrichment_jobs SET status=?,slots=?,finished_at=?,"
                "failure_code='' WHERE job_id=?",
                (READY, json.dumps(safe, ensure_ascii=False), self._clock(), str(job_id)))

    def finish_failed(self, job_id: str, failure_code: str) -> None:
        code = failure_code if failure_code in FAILURE_CODES else "internal_error"
        job = self.get(job_id)
        retryable = (job is not None and job.attempts < MAX_ATTEMPTS
                     and code in {"timeout", "resource_limit", "internal_error"})
        with self.conn:
            self.conn.execute(
                "UPDATE ai_enrichment_jobs SET status=?,failure_code=?,finished_at=? "
                "WHERE job_id=?",
                (PENDING if retryable else FAILED, code,
                 0.0 if retryable else self._clock(), str(job_id)))

    def mark_stale(self, job_id: str) -> None:
        """Bằng chứng đã đổi trong lúc suy luận. Kết quả KHÔNG được gắn vào đâu."""
        with self.conn:
            self.conn.execute(
                "UPDATE ai_enrichment_jobs SET status=?,failure_code=?,finished_at=? "
                "WHERE job_id=?", (STALE, "stale_input", self._clock(), str(job_id)))

    def reconcile_startup(self, *, stale_after_s: float = STALE_RUNNING_S) -> dict:
        """Dọn sau một lần khởi động lại. `RUNNING` cũ KHÔNG còn chạy.

        Tiến trình sở hữu chúng đã chết; giả vờ chúng vẫn chạy nghĩa là hàng đợi
        tắc mãi mãi vì một job không ai còn theo dõi.
        """
        now = self._clock()
        with self.conn:
            revived = self.conn.execute(
                "UPDATE ai_enrichment_jobs SET status=?,started_at=0 "
                "WHERE status=? AND attempts < ?", (PENDING, RUNNING, MAX_ATTEMPTS)).rowcount
            abandoned = self.conn.execute(
                "UPDATE ai_enrichment_jobs SET status=?,failure_code=?,finished_at=? "
                "WHERE status=? AND attempts >= ?",
                (FAILED, "internal_error", now, RUNNING, MAX_ATTEMPTS)).rowcount
            expired = self.conn.execute(
                "UPDATE ai_enrichment_jobs SET status=?,failure_code=?,finished_at=? "
                "WHERE status=? AND created_at < ?",
                (FAILED, "stale_input", now, PENDING, now - stale_after_s)).rowcount
        return {"revived": revived, "abandoned": abandoned, "expired": expired}

    def prune(self, *, retention_s: float = COMPLETED_RETENTION_S) -> int:
        cutoff = self._clock() - retention_s
        with self.conn:
            return self.conn.execute(
                "DELETE FROM ai_enrichment_jobs WHERE status IN (?,?,?) AND finished_at < ?",
                (READY, FAILED, STALE, cutoff)).rowcount

    # --- đọc ---

    def _row(self, row) -> EnrichmentJob:
        return EnrichmentJob(
            job_id=row[0], incident_id=row[1], fingerprint=row[2], locale=row[3],
            provider=row[4], model_version=row[5], contract_version=row[6],
            status=row[7], attempts=row[8], failure_code=row[9],
            slots=json.loads(row[10] or "{}"), created_at=row[11],
            started_at=row[12], finished_at=row[13])

    _SELECT = ("SELECT job_id,incident_id,fingerprint,locale,provider,model_version,"
               "contract_version,status,attempts,failure_code,slots,created_at,"
               "started_at,finished_at FROM ai_enrichment_jobs ")

    def get(self, job_id: str) -> EnrichmentJob | None:
        row = self.conn.execute(self._SELECT + "WHERE job_id=?", (str(job_id),)).fetchone()
        return self._row(row) if row else None

    def oldest_pending(self) -> EnrichmentJob | None:
        """Job đang chờ CŨ NHẤT, không claim. Runner dùng để so thứ tự.

        Chỉ đọc: quyết định chạy cái nào là việc của runner, và `claim` mới là
        chỗ đổi trạng thái.
        """
        row = self.conn.execute(
            self._SELECT + "WHERE status=? ORDER BY created_at,job_id LIMIT 1",
            (PENDING,)).fetchone()
        return self._row(row) if row else None

    def by_fingerprint(self, fingerprint_value: str) -> EnrichmentJob | None:
        """Job MỚI NHẤT cho khoá này. Khoá là danh tính, nên khớp là khớp toàn phần."""
        row = self.conn.execute(
            self._SELECT + "WHERE fingerprint=? ORDER BY created_at DESC LIMIT 1",
            (str(fingerprint_value),)).fetchone()
        return self._row(row) if row else None

    def ready_slots(self, fingerprint_value: str) -> dict:
        """Ô văn xuôi an toàn cho ĐÚNG khoá này, hoặc rỗng.

        Không bao giờ nới lỏng phép so: một hàng `READY` với khoá khác là văn
        xuôi của một dữ liệu khác, và gắn nó vào đây là nói dối có thẩm quyền.
        """
        job = self.by_fingerprint(fingerprint_value)
        if job is None or job.status != READY:
            return {}
        if job.fingerprint != str(fingerprint_value):
            return {}
        return dict(job.slots)

    def counts(self) -> dict:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) FROM ai_enrichment_jobs GROUP BY status").fetchall()
        return {status: count for status, count in rows}
