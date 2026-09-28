"""Tuyên bố công khai phải khớp mã, hoặc không được viết ra.

Đợt kiểm tra 27/09/2026 tìm thấy các câu trong README/CHANGELOG/DISCLAIMER mà
mã không chống đỡ: "ten sections" (mã có 11), "Nothing is uploaded" (có đường
Telegram opt-in), "restricted capabilities" cho agent (unit không đặt
CapabilityBoundingSet), và lời "đã sửa và xác minh" watchdog trong khi journal
ghi 41 lần timeout sau đó. Các bài dưới đây giữ những câu đó khỏi quay lại.
"""

from __future__ import annotations

import re
from pathlib import Path

from shield.report.template import SECTIONS

ROOT = Path(__file__).resolve().parent.parent
NUMBER_WORDS = {9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}
PUBLIC = ["README.md", "CHANGELOG.md", "DISCLAIMER.md", "docs/QUICK_START.md",
          "docs/DEMO_SCENARIOS.md", "docs/ARCHITECTURE.md", "docs/SECURITY_MODEL.md"]


def _read(relative: str) -> str:
    text = (ROOT / relative).read_text(encoding="utf-8")
    if relative == "CHANGELOG.md":
        # Mục đính chính trích lại nguyên văn các câu sai; chỉ kiểm phần mô tả.
        start = text.index("### Documentation corrections")
        text = text[:start] + text[text.index("## [Beta 1.0]"):]
    return text


def test_the_report_section_count_matches_the_template():
    count = NUMBER_WORDS[len(SECTIONS)]
    assert f"{count} fixed sections" in _read("README.md")
    assert f"{count} sections" in _read("docs/QUICK_START.md")
    assert f"{len(SECTIONS)} sections" in _read("docs/ARCHITECTURE.md")
    for wrong in set(NUMBER_WORDS.values()) - {count}:
        for relative in PUBLIC:
            assert f"{wrong} fixed sections" not in _read(relative), relative
            assert f"the {wrong} sections" not in _read(relative), relative


def test_no_document_claims_nothing_ever_leaves_the_machine():
    """Telegram opt-in tồn tại trong mã; câu tuyệt đối là sai."""
    assert "api.telegram.org" in _read("shield/agent/notifier.py")
    for relative in PUBLIC + ["docs/PRIVACY.md"]:
        text = _read(relative)
        assert "Nothing is uploaded." not in text, relative
        assert "All data stays on the machine." not in text, relative


def test_agent_capabilities_are_described_as_they_are():
    unit = _read("systemd/shield-agent.service")
    restricted = re.search(r"^CapabilityBoundingSet=", unit, re.MULTILINE) is not None
    readme = _read("README.md")
    agent_paragraph = readme[readme.index("- The **agent** runs as root"):]
    agent_paragraph = agent_paragraph[:agent_paragraph.index("\n- ")]
    if not restricted:
        assert "restricted\n  capabilities" not in agent_paragraph
        assert "does **not** drop root capabilities" in agent_paragraph


def test_unmeasured_numbers_are_not_advertised():
    """Không có benchmark thời gian Q&A và không có cách đếm lại '58 rule'."""
    for relative in PUBLIC + ["docs/RELEASE_NOTES_BETA_1.0.md", "docs/HUONG_DAN_SU_DUNG.md"]:
        text = _read(relative)
        assert "roughly a millisecond" not in text, relative
        assert "khoảng một mili giây" not in text, relative
        assert "58 rule identifiers" not in text, relative
        assert "58 detection rule identifiers" not in text, relative


def test_the_watchdog_is_not_claimed_as_proven():
    readme = _read("README.md")
    assert "zero watchdog timeouts. That is evidence" not in readme
    assert "Watchdog stability is not yet proven" in readme
