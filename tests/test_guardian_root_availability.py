"""Guardian phải nói đúng thứ nó THỰC SỰ biết.

Trước bản sửa này, cây được bảo vệ biến mất và cây bị kẻ tấn công sửa đều ra
cùng một câu: `GUARDIAN_INSTALLATION_CHANGED`. `hash_tree` trên cây không tồn
tại trả về `{}`, nên mọi đường dẫn từng biết đều thành "đã đổi" — một lần nâng
cấp bình thường sẽ báo 125 file thay đổi, đọc y hệt một vụ xoá sạch cài đặt.

Đo trên máy thật: `postinst` chạy `venv --clear` rồi `pip install`, và cây được
bảo vệ KHÔNG tồn tại trong 3,67 giây. Timer chạy mỗi 60 giây, nên xác suất rơi
đúng cửa sổ đó là ~6% mỗi lần nâng cấp.

Không bài nào ở đây tạo ra lòng tin. Ngữ cảnh gói là ngữ cảnh; gói không được
ký, không có repo, và `md5sums` là tính toàn vẹn chứ không phải tính xác thực.
"""

from __future__ import annotations

import json

import pytest

from shield.guardian.__main__ import (
    check_installation_integrity,
    package_context,
    package_manager_context,
    protected_root_state,
)
from shield.security.tamper import signed_snapshot


def _cay(tmp_path, so_file=5):
    root = tmp_path / "shield"
    (root / "agent").mkdir(parents=True)
    for i in range(so_file):
        (root / "agent" / f"m{i}.py").write_text(f"# {i}\n")
    return root


def _anh_chup(root):
    return {"snapshot": signed_snapshot(root, b"")}


def _rules(findings):
    return [f["rule_id"] for f in findings]


# --- 1. cây còn đó, một file đổi ---


def test_a_changed_file_is_still_an_installation_change(tmp_path):
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    (root / "agent" / "m2.py").write_text("# đã bị sửa\n")

    findings, snapshot = check_installation_integrity(root, truoc, b"")

    assert _rules(findings) == ["GUARDIAN_INSTALLATION_CHANGED"]
    assert findings[0]["severity"] == "critical"
    assert findings[0]["evidence"]["changed"] == ["agent/m2.py"]


# --- 2. cây biến mất hoàn toàn ---


def test_a_missing_root_is_unavailable_not_a_mass_change(tmp_path):
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    for path in sorted(root.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    root.rmdir()

    findings, snapshot = check_installation_integrity(root, truoc, b"")

    assert _rules(findings) == ["GUARDIAN_PROTECTED_ROOT_UNAVAILABLE"]
    ev = findings[0]["evidence"]
    assert ev["reason"] == "missing"
    assert ev["exists"] is False
    assert ev["readable"] is False
    assert ev["verified"] is False, "không kiểm tra được KHÁC với kiểm tra đạt"
    assert ev["previous_snapshot_files"] == 5
    assert "changed" not in ev, "không được dựng diff giả với ảnh chụp cũ"
    assert "125" not in findings[0]["detail"]


def test_a_missing_root_does_not_overwrite_the_baseline(tmp_path):
    """Ghi đè bằng ảnh chụp rỗng là âm thầm lấy lại nền — cây quay lại ĐÃ BỊ
    SỬA sẽ được coi là bình thường."""
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    for path in sorted(root.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    root.rmdir()

    _, snapshot = check_installation_integrity(root, truoc, b"")
    assert snapshot == truoc["snapshot"]


# --- 3. cây không đọc được ---


def test_an_unreadable_root_is_also_unavailable(tmp_path):
    import os

    if os.geteuid() == 0:
        pytest.skip("root đọc được mọi thứ — quyền không chặn được")
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    root.chmod(0o000)
    try:
        findings, snapshot = check_installation_integrity(root, truoc, b"")
    finally:
        root.chmod(0o755)

    assert _rules(findings) == ["GUARDIAN_PROTECTED_ROOT_UNAVAILABLE"]
    assert findings[0]["evidence"]["reason"] == "permission_denied"
    assert snapshot == truoc["snapshot"]


def test_a_file_where_a_directory_belongs_is_unavailable(tmp_path):
    root = tmp_path / "shield"
    root.write_text("đây không phải thư mục")
    ok, ly_do = protected_root_state(root)
    assert (ok, ly_do) == (False, "not_a_directory")


# --- 4 & 5. cây biến mất rồi quay lại ---


def test_verification_resumes_when_an_unchanged_root_returns(tmp_path):
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    noi_dung = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}

    for path in sorted(root.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    root.rmdir()
    findings, snapshot = check_installation_integrity(root, truoc, b"")
    assert _rules(findings) == ["GUARDIAN_PROTECTED_ROOT_UNAVAILABLE"]

    for path, data in noi_dung.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    findings, _ = check_installation_integrity(root, {"snapshot": snapshot}, b"")
    assert findings == [], "cây quay lại y nguyên thì phải im lặng"


def test_a_root_that_returns_modified_is_still_detected(tmp_path):
    """Đây là bài quan trọng nhất của mục A: nếu ảnh chụp bị lấy lại nền lúc
    cây vắng mặt, thì sửa đổi ở đây sẽ biến mất không dấu vết."""
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    noi_dung = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}

    for path in sorted(root.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    root.rmdir()
    _, snapshot = check_installation_integrity(root, truoc, b"")

    for path, data in noi_dung.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / "agent" / "m0.py").write_bytes(b"# cua ke tan cong\n")

    findings, _ = check_installation_integrity(root, {"snapshot": snapshot}, b"")
    assert _rules(findings) == ["GUARDIAN_INSTALLATION_CHANGED"]
    assert findings[0]["evidence"]["changed"] == ["agent/m0.py"]


# --- 6, 7, 9. ngữ cảnh KHÔNG BAO GIỜ là lòng tin ---


def test_package_context_never_lowers_the_severity(tmp_path):
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    (root / "agent" / "m1.py").write_text("# đã đổi\n")

    findings, _ = check_installation_integrity(
        root, truoc, b"", {"package_manager_context": "true"})

    assert findings[0]["severity"] == "critical", \
        "trùng thời điểm với một giao dịch gói KHÔNG phải là xác thực"
    assert findings[0]["evidence"]["package_manager_context"] == "true"
    assert findings[0]["evidence"]["authenticity"] == "unverified"


@pytest.mark.parametrize("gia_mao", [
    {"trusted": True}, {"signed": True}, {"upgrade_in_progress": True},
    {"parent_process": "apt"}, {"SHIELD_TRUSTED_UPGRADE": "1"},
])
def test_no_context_field_can_suppress_or_downgrade(tmp_path, gia_mao):
    """Marker, biến môi trường, tiến trình cha là apt — tất cả đều do root tạo
    ra được, nên không cái nào được đổi kết luận."""
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    (root / "agent" / "m3.py").write_text("# đã đổi\n")

    findings, _ = check_installation_integrity(root, truoc, b"", gia_mao)

    assert _rules(findings) == ["GUARDIAN_INSTALLATION_CHANGED"]
    assert findings[0]["severity"] == "critical"


def test_the_evidence_never_claims_authenticity(tmp_path):
    root = _cay(tmp_path)
    truoc = _anh_chup(root)
    (root / "agent" / "m4.py").write_text("# đã đổi\n")
    findings, _ = check_installation_integrity(root, truoc, b"")
    ev = json.dumps(findings[0]["evidence"])
    assert '"authenticity": "unverified"' in ev
    assert findings[0]["evidence"]["signed"] is False


# --- 8. thiếu metadata dpkg thì vẫn chạy ---


def test_missing_dpkg_metadata_degrades_to_unknown(tmp_path, monkeypatch):
    import shield.guardian.__main__ as G

    monkeypatch.setattr(G, "DPKG_INFO_DIR", tmp_path / "khong-co")
    monkeypatch.setattr(G, "installed_package_version", lambda *a, **k: "")

    ctx = package_context(tmp_path, ["a.py", "b.py"], {})
    assert ctx["package_owned_changed"] == "unknown"
    assert ctx["non_package_owned_changed"] == "unknown"
    assert ctx["package_version"] == "unknown"
    assert ctx["changed_total"] == 2
    assert ctx["authenticity"] == "unverified"


def test_the_first_run_reports_unknown_not_false(tmp_path):
    """Chưa có mốc để so thì là "chưa biết", không phải "không có giao dịch"."""
    status = tmp_path / "status"
    status.write_text("x")
    assert package_manager_context({}, status)["package_manager_context"] == "unknown"


def test_a_dpkg_transaction_since_the_last_check_is_reported(tmp_path):
    status = tmp_path / "status"
    status.write_text("x")
    moc = status.stat().st_mtime
    assert package_manager_context({"dpkg_status_mtime": moc}, status)[
        "package_manager_context"] == "false"
    assert package_manager_context({"dpkg_status_mtime": moc - 100}, status)[
        "package_manager_context"] == "true"


def test_package_owned_paths_are_counted_against_absolute_paths(tmp_path, monkeypatch):
    import shield.guardian.__main__ as G

    info = tmp_path / "info"
    info.mkdir()
    root = tmp_path / "shield"
    (info / f"{G.PACKAGE_NAME}.list").write_text(f"{root}/agent/m0.py\n/etc/other\n")
    monkeypatch.setattr(G, "DPKG_INFO_DIR", info)
    monkeypatch.setattr(G, "installed_package_version", lambda *a, **k: "9.9")

    ctx = package_context(root, ["agent/m0.py", "agent/m1.py"], {})
    assert ctx["package_owned_changed"] == 1
    assert ctx["non_package_owned_changed"] == 1


# --- bất biến i18n: agent sinh mã, giao diện dịch ---


def test_every_guardian_rule_has_both_translations():
    """Lỗi i18n đã xảy ra ba lần trong dự án này, và chưa có bất biến nào bắt
    buộc rule mới phải có bản dịch. Thiếu bản dịch nghĩa là người dùng tiếng
    Anh đọc được một mã máy, hoặc một câu tiếng Việt."""
    import re
    from pathlib import Path

    from shield.ui.i18n import STRINGS

    nguon = Path("shield/guardian/__main__.py").read_text(encoding="utf-8")
    rule_ids = set(re.findall(r'"rule_id":\s*"(GUARDIAN_[A-Z_]+)"', nguon))
    assert rule_ids, "không tìm thấy rule nào — biểu thức đã lệch khỏi mã"
    thieu = [f"alert.{r}.{phan}" for r in sorted(rule_ids) for phan in ("title", "detail")
             if f"alert.{r}.{phan}" not in STRINGS]
    assert not thieu, f"thiếu bản dịch: {thieu}"
