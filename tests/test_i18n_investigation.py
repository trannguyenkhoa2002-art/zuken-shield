"""Màn hình điều tra mới nói được CẢ tiếng Việt lẫn tiếng Anh.

Kiểm tra ngày 30/09/2026 thấy: dòng trạng thái workspace, khung chi tiết, nhãn
"NEW", bộ lọc trạng thái và cột lý do của vùng xám chỉ có tiếng Anh; 16 mục
bảng dịch để nguyên tiếng Anh ở phía tiếng Việt.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

from shield.security.workspace import TabState, WorkspaceFilter
from shield.ui import gray_zone_view, workspace_view
from shield.ui.i18n import STRINGS

ROOT = Path(__file__).resolve().parent.parent


def test_workspace_status_and_detail_are_translated():
    tab = TabState(WorkspaceFilter())
    tab.offer({"ts": time.time(), "kind": "k", "source": "s", "data": {}, "raw": ""})
    tab.pause()
    tab.offer({"ts": time.time(), "kind": "k", "source": "s", "data": {}, "raw": ""})
    vi, en = workspace_view.status_text(tab, "vi"), workspace_view.status_text(tab, "en")
    assert "dòng" in vi and "đang giữ" in vi and "rows" not in vi and "held" not in vi
    assert "rows" in en and "held" in en
    event = {"data": {"a": 1}, "raw": ""}
    assert "Bản chuẩn hoá" in workspace_view.detail_text(event, "vi")
    assert "không có dòng log gốc" in workspace_view.detail_text(event, "vi")
    assert "Normalized" in workspace_view.detail_text(event, "en")
    assert "MỚI" in workspace_view.group_label({"new": True, "label": "x", "count": 1}, "vi")


def test_gray_zone_reasons_are_built_in_the_users_language():
    near = {"kind": "below_threshold", "reason": "3 failed logins, threshold is 5",
            "evidence": {"gray_zone": {"observed": 3, "threshold": 5}}}
    assert gray_zone_view.reason_text(near, "vi") == "3/5 — chưa tới ngưỡng phát hiện"
    assert gray_zone_view.reason_text(near, "en") == "3/5 — below the detection threshold"
    low = {"kind": "low_confidence", "risk_score": 82, "evidence_confidence": 60}
    assert "độ tin cậy bằng chứng chỉ 60/100" in gray_zone_view.reason_text(low, "vi")
    muted = {"kind": "suppressed", "reason": "suppressed by policy: known admin script"}
    assert gray_zone_view.reason_text(muted, "vi") == "Bị policy tắt tiếng: known admin script"


def test_the_stored_gray_zone_entry_keeps_what_the_ui_needs(tmp_path):
    from shield.agent.store import Store
    from shield.common.models import Alert
    from shield.security.gray_zone import GrayZoneStore

    gray = GrayZoneStore(Store(tmp_path / "s.db").conn)
    entry = gray.record(Alert(time.time(), "LOCAL_SSH_BRUTEFORCE", "info", "t", "d", "x",
                              evidence={"gray_zone": {"reason": "r", "observed": 3, "threshold": 5}}),
                        "below_threshold", "r")
    assert gray_zone_view.reason_text(entry, "vi").startswith("3/5")


def test_gray_zone_state_filter_labels_exist_in_both_languages():
    for state in ("open", "promoted", "dismissed"):
        vi, en = STRINGS[f"gray.state.{state}"]
        assert vi and en and vi != en


def test_the_i18n_audit_finds_no_missing_keys_or_placeholder_mismatch():
    out = subprocess.run([sys.executable, str(ROOT / "scripts/check-i18n.py")],
                         capture_output=True, text=True, cwd=ROOT).stdout
    assert re.search(r"MISSING keys \(0\)", out), out[:800]
    assert "PLACEHOLDER mismatch vi/en (0)" in out
    assert "EMPTY translations (0)" in out


def test_no_display_text_bypasses_translation():
    """Strict: không khoá thiếu, không chữ hiển thị viết cứng ngoài danh sách cho phép.
    Dòng ghi công và chữ "online" giữ nguyên có chủ ý (test_ui_wiring,
    test_online_devices)."""
    result = subprocess.run([sys.executable, str(ROOT / "scripts/check-i18n.py"), "--strict"],
                            capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, result.stdout[:1500]
    assert "HARDCODED display text (0)" in result.stdout

