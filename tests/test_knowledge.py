"""Kho tri thức threat-intel: nguồn gốc, chữ ký, thu hồi (mục 5.3).

Threat-intel là dữ liệu **do người khác viết** mà Shield dùng để ra quyết định
về máy của bạn. Một bản ghi bị đầu độc nói gateway của bạn là máy chủ C2 sẽ
khiến Shield đề xuất chặn đúng thứ giữ cho máy online.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from shield.agent.store import Store
from shield.security.intel import KnowledgeFeedProvider, normalize_indicator
from shield.security.knowledge import (
    TRUSTED,
    UNTRUSTED,
    KnowledgeStore,
    UntrustedContent,
    document_id,
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "shield.db", allow_migration=True)


@pytest.fixture()
def knowledge(store):
    return KnowledgeStore(store.conn)


def _feed(*indicators, verdict="malicious") -> bytes:
    return json.dumps({
        "schema_version": 1,
        "indicators": [{"value": value, "verdict": verdict} for value in indicators],
    }).encode()


# --- nguồn gốc bắt buộc ---


def test_a_document_records_where_it_came_from(knowledge):
    """Một chỉ dấu không nói được nó đến từ đâu thì không dùng được để giải
    thích bất cứ điều gì."""
    doc_id = knowledge.import_document(
        _feed("203.0.113.9"), source="feed-noi-bo", signature_status="verified",
        fetched_ts=1000.0)
    record = knowledge.documents()[0]
    assert record["doc_id"] == doc_id
    assert record["source"] == "feed-noi-bo"
    assert record["signature_status"] == "verified"
    assert record["trust_tier"] == TRUSTED
    assert record["fetched_ts"] == 1000.0 and record["imported_ts"] > 0
    assert record["entry_count"] == 1


def test_the_document_id_is_its_content_hash(knowledge):
    """Cùng tài liệu nhập hai lần là một tài liệu, không phải hai."""
    content = _feed("203.0.113.9")
    first = knowledge.import_document(content, source="a", signature_status="verified")
    second = knowledge.import_document(content, source="a", signature_status="verified")
    assert first == second == document_id(content)
    assert knowledge.counts()["documents"] == 1


# --- không nhập dữ liệu chưa xác thực vào kho tin cậy ---


def test_an_unsigned_document_is_refused_from_the_trusted_tier(knowledge):
    with pytest.raises(UntrustedContent, match="đã ký"):
        knowledge.import_document(_feed("1.2.3.4"), source="x",
                                  signature_status="unsigned")


def test_an_invalid_signature_is_refused_by_every_tier(knowledge):
    """Chữ ký SAI khác hẳn không có chữ ký: nó nghĩa là ai đó đã sửa nội dung
    sau khi ký."""
    for require in (True, False):
        with pytest.raises(UntrustedContent, match="bị sửa"):
            knowledge.import_document(_feed("1.2.3.4"), source="x",
                                      signature_status="invalid",
                                      require_signature=require)


def test_importing_unsigned_content_must_be_explicit(knowledge):
    doc_id = knowledge.import_document(_feed("1.2.3.4"), source="x",
                                       signature_status="unsigned",
                                       require_signature=False)
    assert knowledge.documents()[0]["trust_tier"] == UNTRUSTED
    assert doc_id


def test_a_malformed_document_is_refused(knowledge):
    for bad in (b"not json", b"[]", json.dumps({"schema_version": 2}).encode(),
                json.dumps({"schema_version": 1}).encode(),
                json.dumps({"schema_version": 1,
                            "indicators": [{"value": "1.2.3.4",
                                            "verdict": "definitely"}]}).encode()):
        with pytest.raises(ValueError):
            knowledge.import_document(bad, source="x", signature_status="verified")


# --- nguồn ngoài chỉ đối chứng ---


def test_every_lookup_is_marked_corroboration_only(knowledge):
    """Bất biến nằm trong DỮ LIỆU, không trong một quy ước mà lớp sau phải nhớ."""
    knowledge.import_document(_feed("203.0.113.9"), source="x",
                              signature_status="verified")
    matches = knowledge.lookup(*normalize_indicator("203.0.113.9"))
    assert matches and all(m["corroboration_only"] for m in matches)


def test_an_untrusted_document_cannot_decide_the_verdict(knowledge):
    """Bậc `untrusted` vẫn hiện ra để người điều tra thấy, nhưng nó không đổi
    kết luận."""
    knowledge.import_document(_feed("192.168.1.1"), source="nguon-la",
                              signature_status="unsigned", require_signature=False)
    provider = KnowledgeFeedProvider(knowledge)
    result = run(provider.lookup(*normalize_indicator("192.168.1.1")))
    assert result.verdict == "unknown", "nguồn chưa ký đã quyết định được kết luận"
    assert result.details["untrusted_documents"] == 1
    assert result.details["documents"], "nguồn chưa ký bị giấu khỏi người điều tra"


def test_a_trusted_document_decides_the_verdict(knowledge):
    knowledge.import_document(_feed("203.0.113.9"), source="x",
                              signature_status="verified")
    result = run(KnowledgeFeedProvider(knowledge).lookup(
        *normalize_indicator("203.0.113.9")))
    assert result.verdict == "malicious"
    assert result.corroboration_only is True


def test_conflicting_trusted_sources_report_the_stronger_verdict(knowledge):
    """Nếu một nguồn nói malicious và một nguồn nói clean, câu trả lời an toàn
    là nêu ra cái đáng lo — và người điều tra thấy cả hai."""
    knowledge.import_document(_feed("203.0.113.9", verdict="clean"), source="a",
                              signature_status="verified")
    knowledge.import_document(_feed("203.0.113.9", verdict="malicious"), source="b",
                              signature_status="verified")
    result = run(KnowledgeFeedProvider(knowledge).lookup(
        *normalize_indicator("203.0.113.9")))
    assert result.verdict == "malicious"
    assert len(result.details["documents"]) == 2


def test_intel_alone_can_never_support_a_claim(store):
    """Mục 5.3 ở tầng kết luận: một khẳng định mà MỌI bằng chứng đều là nguồn
    ngoài thì không được mang trạng thái `supported`, dù đã ký và dù có bao
    nhiêu nguồn cùng nói."""
    from shield.ai.contracts import Hypothesis, InvestigationRequest, InvestigationResult
    from shield.ai.validator import EvidenceValidator
    from shield.evidence.models import EvidenceKind
    from shield.evidence.queries import EvidenceQueries

    graph = store.graph
    refs = tuple(f"intel:doc-{i}" for i in range(3))
    with store.conn:
        for ref in refs:
            graph.record_evidence(ref, evidence_kind=EvidenceKind.EXTERNAL_INTEL,
                                  ts=1000.0, trust="local")

    queries = EvidenceQueries(store.conn, caller="t")
    validated, _ = EvidenceValidator(queries).validate(
        InvestigationResult(investigation_id="i", incident_id="inc",
                            hypotheses=(Hypothesis("H1", "Máy đã bị chiếm", "supported",
                                                   refs, confidence_label="high"),)),
        InvestigationRequest(investigation_id="i", incident_id="inc",
                             allowed_evidence_refs=frozenset(refs)))
    assert validated.hypotheses[0].status == "unconfirmed"
    assert "nguồn ngoài" in validated.hypotheses[0].downgrade_reason


# --- thu hồi ---


def test_revoking_a_document_takes_effect_immediately(knowledge):
    """Một tài liệu hoá ra bị đầu độc phải ngừng có hiệu lực NGAY, không phải
    sau lần khởi động sau."""
    doc_id = knowledge.import_document(_feed("192.168.1.1"), source="bi-dau-doc",
                                       signature_status="verified")
    assert knowledge.lookup(*normalize_indicator("192.168.1.1"))

    assert knowledge.revoke(doc_id, "nguồn bị chiếm") is True
    assert knowledge.lookup(*normalize_indicator("192.168.1.1")) == []
    result = run(KnowledgeFeedProvider(knowledge).lookup(
        *normalize_indicator("192.168.1.1")))
    assert result.verdict == "unknown"


def test_revoking_keeps_the_record_for_the_post_mortem(knowledge):
    """Xoá đi thì không ai trả lời được câu hỏi sau sự cố: kết luận hôm qua
    dựa trên cái gì, và cái đó giờ ra sao?"""
    doc_id = knowledge.import_document(_feed("1.2.3.4"), source="x",
                                       signature_status="verified")
    knowledge.revoke(doc_id, "lý do cụ thể")
    record = knowledge.documents()[0]
    assert record["revoked"] is True
    assert record["revoked_reason"] == "lý do cụ thể"
    assert record["revoked_ts"] > 0


def test_revoking_twice_reports_no_change(knowledge):
    doc_id = knowledge.import_document(_feed("1.2.3.4"), source="x",
                                       signature_status="verified")
    assert knowledge.revoke(doc_id) is True
    assert knowledge.revoke(doc_id) is False


def test_reimporting_a_revoked_document_does_not_un_revoke_it(knowledge):
    """Nếu nó bị đầu độc lần trước thì nội dung giống hệt vẫn bị đầu độc."""
    content = _feed("1.2.3.4")
    doc_id = knowledge.import_document(content, source="x", signature_status="verified")
    knowledge.revoke(doc_id, "bị đầu độc")
    knowledge.import_document(content, source="x", signature_status="verified")
    assert knowledge.documents()[0]["revoked"] is True
    assert knowledge.lookup(*normalize_indicator("1.2.3.4")) == []


def test_a_revocation_can_be_undone_deliberately(knowledge):
    doc_id = knowledge.import_document(_feed("1.2.3.4"), source="x",
                                       signature_status="verified")
    knowledge.revoke(doc_id)
    assert knowledge.unrevoke(doc_id) is True
    assert knowledge.lookup(*normalize_indicator("1.2.3.4"))


# --- dựng lại index ---


def test_rebuilding_the_index_removes_revoked_entries(knowledge):
    doc_id = knowledge.import_document(_feed("1.2.3.4", "5.6.7.8"), source="x",
                                       signature_status="verified")
    knowledge.import_document(_feed("9.9.9.9"), source="y", signature_status="verified")
    knowledge.revoke(doc_id)
    result = knowledge.rebuild_index()
    assert result["revoked_removed"] == 2
    assert knowledge.counts()["indicators"] == 1


def test_rebuilding_a_healthy_index_changes_nothing(knowledge):
    """Nếu dựng lại mà số chỉ dấu đổi thì index đã lệch, và đó là thứ đáng biết."""
    knowledge.import_document(_feed("1.2.3.4", "5.6.7.8"), source="x",
                              signature_status="verified")
    result = knowledge.rebuild_index()
    assert result["before"] == result["after"] == 2


def test_rebuilding_removes_orphaned_indicators(knowledge, store):
    """Khoá ngoại chặn không cho TẠO orphan trong lúc chạy bình thường — nhưng
    đường phục hồi database dựng lại từng bảng riêng và không ép khoá ngoại
    (xem `Store._salvage_table`). Một database vừa được cứu khỏi hỏng hóc có
    thể có chỉ dấu trỏ tới tài liệu không còn, và khi đó chúng vẫn được tra ra
    như thể còn hiệu lực.
    """
    knowledge.import_document(_feed("1.2.3.4"), source="x", signature_status="verified")
    store.conn.execute("PRAGMA foreign_keys=OFF")
    try:
        with store.conn:
            store.conn.execute(
                "INSERT INTO intel_indicators(indicator_type,indicator,verdict,doc_id) "
                "VALUES('ip','8.8.8.8','malicious','sha256:khong-ton-tai')")
    finally:
        store.conn.execute("PRAGMA foreign_keys=ON")
    assert knowledge.rebuild_index()["orphans_removed"] == 1
    assert knowledge.counts()["indicators"] == 1


# --- schema ---


def test_the_knowledge_tables_exist(store):
    have = {row[0] for row in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"intel_documents", "intel_indicators"} <= have
