"""Kho tri thức có nguồn gốc, chữ ký và đường thu hồi (mục 5.3).

Threat-intel là dữ liệu **do người khác viết** mà Shield dùng để ra quyết định
về máy của bạn. Điều đó khiến nó là bề mặt tấn công: một bản ghi bị đầu độc nói
gateway của bạn là máy chủ C2 sẽ khiến Shield đề xuất chặn đúng thứ giữ cho máy
online.

Bốn quy tắc, lấy thẳng từ mục 5.3:

1. **Mọi tài liệu có nguồn, hash, chữ ký, thời điểm tải/nhập và bậc tin cậy.**
   Một chỉ dấu không nói được nó đến từ đâu thì không dùng được để giải thích
   bất cứ điều gì.
2. **Nguồn ngoài chỉ ĐỐI CHỨNG.** Nó không bao giờ một mình xác nhận một máy đã
   bị chiếm. Quy tắc này nằm ở kiểu dữ liệu (`corroboration_only`), không nằm
   trong một dòng chú thích.
3. **Không nhập dữ liệu chưa xác thực vào kho tin cậy.** Không có cờ nào bật
   được điều đó; hàm nhập từ chối thẳng.
4. **Thu hồi và dựng lại index phải làm được.** Một tài liệu hoá ra bị đầu độc
   phải ngừng có hiệu lực NGAY, không phải sau lần khởi động sau.

Thu hồi cố ý KHÔNG xoá tài liệu. Nó đánh dấu. Xoá đi thì không ai trả lời được
câu hỏi sau sự cố: "kết luận hôm qua dựa trên cái gì, và cái đó giờ ra sao?"
"""

from __future__ import annotations

import hashlib
import json
import time

KNOWLEDGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_documents (
    doc_id TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL,
    signature_status TEXT NOT NULL DEFAULT 'unsigned',
    -- trusted | untrusted. Chỉ tài liệu ĐÃ KÝ mới được vào bậc trusted, và
    -- không có cờ nào bật được ngoại lệ.
    trust_tier TEXT NOT NULL DEFAULT 'untrusted',
    fetched_ts REAL NOT NULL DEFAULT 0,
    imported_ts REAL NOT NULL DEFAULT 0,
    entry_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_ts REAL NOT NULL DEFAULT 0,
    revoked_reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS intel_indicators (
    indicator_type TEXT NOT NULL,
    indicator TEXT NOT NULL,
    verdict TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    PRIMARY KEY(indicator_type, indicator, doc_id),
    FOREIGN KEY(doc_id) REFERENCES intel_documents(doc_id)
);
"""

KNOWLEDGE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_intel_indicators_lookup
    ON intel_indicators(indicator_type, indicator);
CREATE INDEX IF NOT EXISTS idx_intel_documents_tier
    ON intel_documents(trust_tier, revoked);
"""

TRUSTED = "trusted"
UNTRUSTED = "untrusted"
VALID_VERDICTS = frozenset({"clean", "suspicious", "malicious"})
MAX_INDICATORS_PER_DOCUMENT = 100_000


class UntrustedContent(ValueError):
    """Nội dung chưa xác thực bị từ chối khỏi kho tin cậy."""


def document_id(content: bytes) -> str:
    """ID = hash nội dung. Cùng tài liệu nhập hai lần là một tài liệu."""
    return "sha256:" + hashlib.sha256(content).hexdigest()


class KnowledgeStore:
    def __init__(self, conn, clock=time.time) -> None:
        self.conn = conn
        self._clock = clock

    # --- nhập ---

    def import_document(self, content: bytes, *, source: str,
                        signature_status: str = "unsigned",
                        fetched_ts: float = 0.0,
                        require_signature: bool = True) -> str:
        """Nhập một tài liệu intel. Trả về `doc_id`.

        `require_signature=True` là mặc định và là điểm thi hành quy tắc 3:
        chỉ tài liệu có chữ ký đã xác minh mới vào bậc `trusted`. Muốn nhập
        nguồn chưa ký thì phải nói ra tường minh, và nó vào bậc `untrusted` —
        nơi nó chỉ đối chứng được, không xác nhận được gì.
        """
        if signature_status not in {"verified", "unsigned", "invalid"}:
            raise ValueError(f"trạng thái chữ ký không hợp lệ: {signature_status!r}")
        if signature_status == "invalid":
            # Chữ ký SAI khác hẳn không có chữ ký: nó nghĩa là ai đó đã sửa nội
            # dung sau khi ký. Không có bậc nào nhận nó.
            raise UntrustedContent("chữ ký không hợp lệ — nội dung đã bị sửa sau khi ký")
        if require_signature and signature_status != "verified":
            raise UntrustedContent(
                "kho tin cậy chỉ nhận tài liệu đã ký; muốn nhập nguồn chưa ký "
                "thì phải đặt require_signature=False và nó sẽ vào bậc untrusted")

        tier = TRUSTED if signature_status == "verified" else UNTRUSTED
        doc_id = document_id(content)
        now = self._clock()
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"tài liệu không phải JSON hợp lệ: {exc}") from exc
        entries = self._entries(payload)

        with self.conn:
            self.conn.execute(
                "INSERT INTO intel_documents(doc_id,source,content_hash,signature_status,"
                "trust_tier,fetched_ts,imported_ts,entry_count) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(doc_id) DO UPDATE SET imported_ts=excluded.imported_ts,"
                # Nhập lại một tài liệu đã thu hồi KHÔNG gỡ thu hồi: nếu nó bị
                # đầu độc lần trước thì nội dung giống hệt vẫn bị đầu độc.
                "source=excluded.source",
                (doc_id, str(source)[:200], doc_id, signature_status, tier,
                 float(fetched_ts or now), now, len(entries)),
            )
            self.conn.execute("DELETE FROM intel_indicators WHERE doc_id=?", (doc_id,))
            for (indicator_type, indicator), verdict in entries.items():
                self.conn.execute(
                    "INSERT OR REPLACE INTO intel_indicators(indicator_type,indicator,"
                    "verdict,doc_id) VALUES(?,?,?,?)",
                    (indicator_type, indicator, verdict, doc_id),
                )
        return doc_id

    @staticmethod
    def _entries(payload) -> dict:
        from shield.security.intel import normalize_indicator

        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise ValueError("tài liệu intel phải là schema v1")
        items = payload.get("indicators")
        if not isinstance(items, list):
            raise ValueError("tài liệu intel thiếu danh sách indicators")
        entries: dict = {}
        for item in items[:MAX_INDICATORS_PER_DOCUMENT]:
            if not isinstance(item, dict) or "value" not in item:
                raise ValueError("chỉ dấu thiếu trường value")
            verdict = str(item.get("verdict", "malicious"))
            if verdict not in VALID_VERDICTS:
                raise ValueError(f"verdict không hợp lệ: {verdict!r}")
            entries[normalize_indicator(str(item["value"]))] = verdict
        return entries

    # --- thu hồi ---

    def revoke(self, doc_id: str, reason: str = "") -> bool:
        """Thu hồi một tài liệu. Có hiệu lực NGAY ở lần tra tiếp theo.

        Không xoá: xoá đi thì không ai trả lời được câu hỏi sau sự cố — "kết
        luận hôm qua dựa trên cái gì, và cái đó giờ ra sao?"
        """
        with self.conn:
            changed = self.conn.execute(
                "UPDATE intel_documents SET revoked=1,revoked_ts=?,revoked_reason=? "
                "WHERE doc_id=? AND revoked=0",
                (self._clock(), str(reason)[:500], str(doc_id)),
            ).rowcount
        return changed > 0

    def unrevoke(self, doc_id: str) -> bool:
        with self.conn:
            changed = self.conn.execute(
                "UPDATE intel_documents SET revoked=0,revoked_ts=0,revoked_reason='' "
                "WHERE doc_id=?", (str(doc_id),)).rowcount
        return changed > 0

    # --- tra cứu ---

    def lookup(self, indicator_type: str, indicator: str) -> list[dict]:
        """Mọi tài liệu CÒN HIỆU LỰC nói gì về chỉ dấu này.

        Tài liệu đã thu hồi không xuất hiện. Tài liệu bậc `untrusted` xuất hiện
        nhưng mang `corroboration_only=True` — người đọc và mọi lớp phía sau
        phải nhìn thấy sự khác biệt đó, chứ không phải tin vào một chú thích.
        """
        rows = self.conn.execute(
            "SELECT i.verdict, d.doc_id, d.source, d.trust_tier, d.signature_status, "
            "d.fetched_ts, d.imported_ts FROM intel_indicators i "
            "JOIN intel_documents d ON d.doc_id=i.doc_id "
            "WHERE i.indicator_type=? AND i.indicator=? AND d.revoked=0 "
            "ORDER BY d.trust_tier DESC, d.imported_ts DESC LIMIT 50",
            (str(indicator_type), str(indicator)),
        ).fetchall()
        return [{
            "verdict": row[0], "doc_id": row[1], "source": row[2],
            "trust_tier": row[3], "signature_status": row[4],
            "fetched_ts": row[5], "imported_ts": row[6],
            # Bất biến của mục 5.3 nằm ở ĐÂY, trong dữ liệu — không phải trong
            # một quy ước mà lớp sau phải nhớ.
            "corroboration_only": True,
        } for row in rows]

    def documents(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT doc_id,source,signature_status,trust_tier,fetched_ts,imported_ts,"
            "entry_count,revoked,revoked_ts,revoked_reason FROM intel_documents "
            "ORDER BY imported_ts DESC LIMIT ?", (max(1, min(int(limit), 500)),),
        ).fetchall()
        return [{
            "doc_id": r[0], "source": r[1], "signature_status": r[2],
            "trust_tier": r[3], "fetched_ts": r[4], "imported_ts": r[5],
            "entry_count": r[6], "revoked": bool(r[7]), "revoked_ts": r[8],
            "revoked_reason": r[9],
        } for r in rows]

    def rebuild_index(self) -> dict:
        """Dựng lại bảng chỉ dấu từ danh sách tài liệu còn hiệu lực.

        Tra cứu đã bỏ qua tài liệu thu hồi, nên việc này KHÔNG cần cho tính
        đúng. Nó cần cho hai thứ khác: thu lại dung lượng sau khi thu hồi hàng
        loạt, và chứng minh được rằng index đang khớp với tài liệu — nếu dựng
        lại mà số chỉ dấu đổi thì index đã lệch, và đó là thứ đáng biết.
        """
        before = self.conn.execute("SELECT COUNT(*) FROM intel_indicators").fetchone()[0]
        with self.conn:
            removed = self.conn.execute(
                "DELETE FROM intel_indicators WHERE doc_id IN "
                "(SELECT doc_id FROM intel_documents WHERE revoked=1)").rowcount
            orphans = self.conn.execute(
                "DELETE FROM intel_indicators WHERE doc_id NOT IN "
                "(SELECT doc_id FROM intel_documents)").rowcount
        after = self.conn.execute("SELECT COUNT(*) FROM intel_indicators").fetchone()[0]
        return {"before": before, "after": after,
                "revoked_removed": removed, "orphans_removed": orphans}

    def counts(self) -> dict:
        return {
            "documents": self.conn.execute(
                "SELECT COUNT(*) FROM intel_documents").fetchone()[0],
            "revoked": self.conn.execute(
                "SELECT COUNT(*) FROM intel_documents WHERE revoked=1").fetchone()[0],
            "trusted": self.conn.execute(
                "SELECT COUNT(*) FROM intel_documents WHERE trust_tier='trusted' "
                "AND revoked=0").fetchone()[0],
            "indicators": self.conn.execute(
                "SELECT COUNT(*) FROM intel_indicators").fetchone()[0],
        }
