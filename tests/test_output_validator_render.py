"""Phase 3A: model có thể nói dối, người dùng vẫn không nhận được lời nói dối.

`EvidenceValidator` đã canh các ref bằng chứng. Thứ nó KHÔNG canh được là con
số và định danh nằm trong CÂU VĂN — một model vượt qua mọi phép kiểm hiện có
vẫn viết được "15 kết nối từ 10.0.0.9" trong khi dữ liệu chuẩn tắc nói 12 và
10.0.0.8. Không ref nào bị bịa, không giả thuyết nào bị hạ cấp, mọi chỉ số đều
xanh, và câu sai đi thẳng tới người đọc.

Mỗi bài dưới đây chứng minh HAI điều cùng lúc: hành vi sai được giữ lại để điều
tra, và nó không xuất hiện trong đầu ra cuối như một sự thật.
"""

from __future__ import annotations

import dataclasses

import pytest

from shield.ai.contracts import Hypothesis, InvestigationRequest, InvestigationResult
from shield.ai.report import OutputValidator, canonical_tokens, render_report
from shield.ai.validator import EvidenceValidator


class _Queries:
    """Kho bằng chứng tối thiểu: hai ref có thật, mọi ref khác không tồn tại."""

    THAT = {
        "ev:aaa": {"evidence_kind": "endpoint_telemetry", "trust": "authenticated"},
        "ev:bbb": {"evidence_kind": "endpoint_telemetry", "trust": "authenticated"},
        "ev:ngoai_pham_vi": {"evidence_kind": "endpoint_telemetry", "trust": "authenticated"},
    }

    def get_evidence(self, ref):
        return self.THAT.get(ref)


def _request():
    return InvestigationRequest(
        investigation_id="inv:1", incident_id="inc:1", window_s=3600.0,
        facts=({"kind": "socket_connect", "remote_ip": "10.0.0.8", "remote_port": 443,
                "count": 12, "pid": 4321},),
        entities=({"id": "process:host:4321:99", "exe": "/usr/bin/curl"},),
        allowed_evidence_refs=frozenset({"ev:aaa", "ev:bbb"}),
    )


def _ket_qua(summary="", statement="một tiến trình đã kết nối ra ngoài",
             refs=("ev:aaa", "ev:bbb"), status="supported", trai=()):
    return InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1", summary=summary,
        hypotheses=(Hypothesis(id="h1", statement=statement, status=status,
                               evidence_refs=tuple(refs),
                               contradicting_evidence_refs=tuple(trai),
                               confidence_label="high"),),
        provider="test", model="fixture", analysed_ts=1.0)


def _chay(result, request=None):
    request = request or _request()
    validator = OutputValidator(EvidenceValidator(_Queries()))
    validated, report, metrics, dropped = validator.validate(result, request)
    return validated, metrics, dropped, render_report(validated, request, metrics)


# --- 7.1–7.2 evidence refs ---


def test_an_invented_event_id_never_reaches_the_final_report():
    goc = _ket_qua(refs=("ev:khong_ton_tai_9f3a", "ev:aaa"))
    validated, metrics, _, report = _chay(goc)

    assert metrics.invented_evidence_refs == 1
    assert "ev:khong_ton_tai_9f3a" not in str(report)
    assert validated.hypotheses[0].evidence_refs == ("ev:aaa",)


def test_an_out_of_scope_reference_never_reaches_the_final_report():
    """`ev:ngoai_pham_vi` TỒN TẠI — nó chỉ không được cấp cho lượt điều tra
    này. Đây là trường hợp nguy hiểm hơn ref bịa: nó tra cứu được."""
    goc = _ket_qua(refs=("ev:ngoai_pham_vi", "ev:aaa"))
    validated, metrics, _, report = _chay(goc)

    assert metrics.out_of_scope_refs == 1
    assert "ngoai_pham_vi" not in str(report)


# --- 7.3–7.5 sự thật tất định trong câu văn ---


@pytest.mark.parametrize("cau,mo_ta", [
    ("15 kết nối từ 10.0.0.9", "sai cả count lẫn IP"),
    ("kết nối tới 10.0.0.9", "sai IP"),
    ("mở cổng 8443", "sai cổng"),
    ("quan sát được 15 lần", "sai count"),
    ("pid 9999 đã chạy", "sai pid"),
    ("event 0123456789abcdef01 xác nhận điều này", "bịa event_id dạng hex"),
])
def test_prose_containing_non_canonical_values_is_dropped(cau, mo_ta):
    goc = _ket_qua(summary=cau)
    validated, metrics, dropped, report = _chay(goc)

    assert metrics.incorrect_deterministic_facts >= 1, mo_ta
    assert metrics.render_fallbacks >= 1
    assert validated.summary == "", "câu chứa giá trị bịa phải bị bỏ CẢ đoạn"
    assert report["prose"]["dropped"] is True
    assert "10.0.0.9" not in str(report) and "9999" not in str(report)


def test_prose_that_only_cites_canonical_values_survives():
    """Không được bỏ nhầm mọi câu: một model trung thực vẫn phải nói được."""
    goc = _ket_qua(summary="12 kết nối từ 10.0.0.8 tới cổng 443")
    validated, metrics, _, report = _chay(goc)

    assert metrics.incorrect_deterministic_facts == 0
    assert metrics.render_fallbacks == 0
    assert validated.summary == "12 kết nối từ 10.0.0.8 tới cổng 443"


def test_the_final_report_shows_canonical_values_not_the_model_ones():
    """Ví dụ đúng như đặc tả: model nói 15 và 10.0.0.9; dữ liệu nói 12 và
    10.0.0.8; đầu ra cuối phải mang dữ liệu."""
    request = _request()
    validated, metrics, _, report = _chay(_ket_qua(summary="15 kết nối từ 10.0.0.9"), request)

    assert report["prose"]["summary"] == ""
    canon = canonical_tokens(request)
    assert "12" in canon and "10.0.0.8" in canon
    assert "15" not in canon and "10.0.0.9" not in canon


# --- 7.6–7.7 severity / timestamp ---


def test_the_model_cannot_set_the_analysed_timestamp_or_provider():
    """`analysed_ts`, `provider`, `model` là trường tất định. Model không đặt
    được chúng vì `InvestigationResult.parse` từ chối trường lạ — ở đây khẳng
    định renderer lấy chúng từ kết quả đã kiểm, không từ câu văn."""
    report = _chay(_ket_qua(summary="mức độ nghiêm trọng là critical"))[3]
    assert report["identity"]["provider"] == "test"
    assert report["identity"]["analysed_ts"] == 1.0
    assert "severity" not in report["identity"]


def test_a_downgraded_hypothesis_loses_its_confidence_label():
    goc = _ket_qua(refs=("ev:khong_co",))
    validated, _, _, report = _chay(goc)
    assert validated.hypotheses[0].status == "insufficient_evidence"
    assert validated.hypotheses[0].confidence_label == "low"
    assert report["hypotheses"][0]["confidence_label"] == "low"


# --- 7.8–7.9 mâu thuẫn và không đủ căn cứ ---


def test_contradicted_and_unsupported_claims_are_counted_separately():
    trai = _chay(_ket_qua(trai=("ev:bbb",)))[1]
    assert trai.contradictory_claims == 1
    thieu = _chay(_ket_qua(refs=("ev:khong_co",)))[1]
    assert thieu.unsupported_claims == 1


def test_a_contradiction_is_visible_in_the_final_report():
    """Mâu thuẫn phải HIỆN RA, không bị dọn đi — khoảng cách giữa "model nói"
    và "Shield kết luận" chính là thông tin."""
    _, _, _, report = _chay(_ket_qua(trai=("ev:bbb",)))
    assert report["hypotheses"][0]["status"] == "contradicted"
    assert report["hypotheses"][0]["contradicting_evidence_refs"] == ["ev:bbb"]


# --- 7.10 bí mật ---


def test_a_secret_in_model_prose_is_redacted_before_the_final_output():
    goc = _ket_qua(summary="khoá là AKIAIOSFODNN7EXAMPLE và mật khẩu password=hunter2")
    validated, _, _, report = _chay(goc)
    ra = str(report) + validated.summary
    assert "AKIAIOSFODNN7EXAMPLE" not in ra
    assert "hunter2" not in ra


# --- 7.12 + 4. i18n ---


def test_the_renderer_emits_keys_not_vietnamese_sentences():
    """Bất biến đã phải học bốn lần trong dự án này: agent sinh mã, giao diện
    dịch. Lý do hạ cấp của validator là câu tiếng Việt — nó KHÔNG được đi ra."""
    from shield.ui.i18n import STRINGS

    _, _, _, report = _chay(_ket_qua(refs=("ev:khong_co",)))
    khoa = report["hypotheses"][0]["downgrade_reason_key"]
    assert khoa.startswith("report.downgrade.")
    assert khoa in STRINGS, f"{khoa} chưa có bản dịch"
    vi, en = STRINGS[khoa]
    assert vi and en and vi != en


def test_every_downgrade_key_the_renderer_can_emit_has_both_translations():
    import inspect

    from shield.ui.i18n import STRINGS
    import shield.ai.report as R

    nguon = inspect.getsource(R)
    import re
    khoa = set(re.findall(r'"(report\.[a-z_.]+)"', nguon))
    thieu = [k for k in khoa if k not in STRINGS]
    assert not thieu, f"thiếu bản dịch: {sorted(thieu)}"


# --- 3. renderer tất định ---


def test_the_same_input_renders_byte_for_byte_identically():
    import json

    request = _request()
    a = _chay(_ket_qua(summary="12 kết nối"), request)[3]
    b = _chay(_ket_qua(summary="12 kết nối"), request)[3]
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_the_deterministic_section_comes_from_the_request_not_the_model():
    request = _request()
    _, _, _, report = _chay(_ket_qua(summary="tôi thấy 99 thực thể"), request)
    assert report["deterministic"]["entity_count"] == len(request.entities)
    assert report["deterministic"]["evidence_refs"] == sorted(request.allowed_evidence_refs)


# --- 6. cổng nghiệm thu của Phase 3A ---


@pytest.mark.parametrize("goc", [
    _ket_qua(summary="15 kết nối từ 10.0.0.9"),
    _ket_qua(refs=("ev:bia_dat",)),
    _ket_qua(refs=("ev:ngoai_pham_vi",)),
    _ket_qua(summary="pid 9999 mở cổng 8443", refs=("ev:bia_dat", "ev:ngoai_pham_vi")),
])
def test_the_final_output_is_always_clean_however_bad_the_original(goc):
    """Model được phép bịa trong bản GỐC. Cổng đo ở ĐẦU RA CUỐI."""
    validated, metrics, _, report = _chay(goc)

    from shield.ai.report import _khong_chuan_tac, canonical_tokens

    prose = report["prose"]["summary"] + " " + " ".join(
        h["prose"] for h in report["hypotheses"])
    assert _khong_chuan_tac(prose, canonical_tokens(_request())) == [], \
        "một giá trị không chuẩn tắc lọt vào câu văn cuối"
    for h in report["hypotheses"]:
        for ref in h["evidence_refs"]:
            assert ref in {"ev:aaa", "ev:bbb"}, f"{ref} lọt ra đầu ra cuối"


# --- 10. bất biến kiến trúc ---


def test_the_report_layer_adds_no_second_universe():
    """Không tạo vũ trụ validation/redactor/truy vấn thứ hai."""
    import inspect

    import shield.ai.report as R

    nguon = inspect.getsource(R)
    assert "from shield.ai.redaction import redact_text" in nguon
    assert "class EvidenceValidator" not in nguon, "không được định nghĩa validator thứ hai"
    assert "sqlite3" not in nguon, "tầng báo cáo không được tự truy vấn database"
    assert "ACTION_SPECS" not in nguon and "ResponseJob" not in nguon, \
        "3A chỉ sinh báo cáo — không chạm tới thực thi hành động"


def test_no_ai_import_on_the_detector_hot_path():
    """AI không được nằm trên đường nóng của detector."""
    from pathlib import Path

    for path in Path("shield/agent/detectors").rglob("*.py"):
        nguon = path.read_text(encoding="utf-8")
        assert "shield.ai" not in nguon, f"{path} import lớp AI"
    assert "shield.ai" not in Path("shield/security/mitre.py").read_text(encoding="utf-8")


def test_dropping_a_hypothesis_statement_does_not_break_the_contract():
    """`Hypothesis` bắt buộc `statement` không rỗng — có lý do, và bản sửa này
    suýt vi phạm nó. Câu bị bỏ phải thành một KHOÁ, không thành chuỗi rỗng."""
    from shield.ai.report import PROSE_DROPPED_KEY

    validated, metrics, dropped, report = _chay(
        _ket_qua(statement="pid 9999 đã mở cổng 8443"))

    h = validated.hypotheses[0]
    assert h.statement_key == PROSE_DROPPED_KEY
    assert h.statement, "hợp đồng cấm statement rỗng"
    assert "9999" not in h.statement and "8443" not in h.statement
    assert report["hypotheses"][0]["prose"] == ""
    assert metrics.render_fallbacks == 1
    assert "hypothesis:h1" in dropped


def test_a_secret_cannot_hide_a_fabricated_number():
    """Thứ tự quan trọng: kiểm giá trị chuẩn tắc TRƯỚC, che bí mật SAU.

    `redact_text` thay CẢ chuỗi khi thấy một bí mật. Làm ngược thứ tự thì một
    model giấu được số liệu bịa chỉ bằng cách chèn thêm một chuỗi trông như
    khoá API — và bộ đếm sẽ báo 0.
    """
    goc = _ket_qua(summary="15 kết nối từ 10.0.0.9, khoá AKIAIOSFODNN7EXAMPLE")
    validated, metrics, dropped, report = _chay(goc)

    assert metrics.incorrect_deterministic_facts == 2, "phải đếm cả 15 lẫn 10.0.0.9"
    assert sorted(dropped["summary"]) == ["10.0.0.9", "15"]
    assert validated.summary == ""
    assert "AKIAIOSFODNN7EXAMPLE" not in str(report)


@pytest.mark.parametrize("goc", [
    _ket_qua(summary="15 kết nối từ 10.0.0.9"),
    _ket_qua(summary="khoá AKIAIOSFODNN7EXAMPLE và pid 9999"),
    _ket_qua(refs=("ev:bia_dat", "ev:ngoai_pham_vi")),
    _ket_qua(statement="event 0123456789abcdef01 tại cổng 8443",
             refs=("ev:bia_dat",)),
])
def test_the_three_phase_3a_gates_hold_on_the_rendered_output(goc):
    """Đo trên CHÍNH bản đã render, không tin bộ đếm."""
    from shield.ai.report import final_output_is_clean

    _, metrics, _, report = _chay(goc)
    cong = final_output_is_clean(report, _request())

    assert cong["invented_evidence_refs"] == 0
    assert cong["out_of_scope_refs"] == 0
    assert cong["incorrect_deterministic_facts"] == 0
    # Bản gốc VẪN được ghi nhận là có bịa — đó là điểm của ba giai đoạn.
    assert metrics.model_misbehaved() is True
