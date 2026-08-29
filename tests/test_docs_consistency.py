"""Tài liệu phải khớp với mã nguồn, và hai bản hướng dẫn phải khớp với nhau.

Tài liệu sai còn tệ hơn không có tài liệu: người đọc tin nó, làm theo nó, và
phát hiện ra nó sai vào đúng lúc họ đang xử lý sự cố. Các test dưới đây bắt
những dạng lệch có thể kiểm bằng máy.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
ARCH = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
# Báo cáo gate là tài liệu NỘI BỘ: nó không đi kèm bản export công khai. Ở đó
# các bài kiểm gate tự bỏ qua thay vì làm đỏ cả bộ test — một bản checkout công
# khai vẫn phải chạy được toàn bộ suite.
_GATE_PATH = ROOT / "RELEASE_GATE_REPORT.md"
GATE = _GATE_PATH.read_text(encoding="utf-8") if _GATE_PATH.exists() else ""
_gate_only = pytest.mark.skipif(not GATE, reason="không có RELEASE_GATE_REPORT.md (bản công khai)")
# Kỷ luật "bộ tài liệu phải nhỏ" là kỷ luật của kho PHÁT TRIỂN. Bản export công
# khai có thêm README công cộng, hướng dẫn kiểm thử, chính sách bảo mật... theo
# đúng yêu cầu của một kho mở, nên ràng buộc này không áp ở đó.
_internal_only = pytest.mark.skipif(
    not GATE, reason="bộ tài liệu công khai lớn hơn có chủ ý")
EN = (ROOT / "docs/USER_GUIDE.md").read_text(encoding="utf-8")
VI = (ROOT / "docs/HUONG_DAN_SU_DUNG.md").read_text(encoding="utf-8")
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


# --- phiên bản ---


@pytest.mark.parametrize("name,text", [("README", README), ("USER_GUIDE", EN),
                                       ("HUONG_DAN", VI)])
def test_the_documented_version_matches_pyproject(name, text):
    """Lệnh cài trong tài liệu trỏ tới một file .deb theo tên. Sai phiên bản
    nghĩa là người dùng gõ một lệnh không chạy được, ngay ở bước đầu tiên."""
    stale = set(re.findall(r"shield-monitor_([0-9][^_]*)_amd64\.deb", text))
    assert stale <= {VERSION}, f"{name} còn trỏ tới phiên bản cũ: {sorted(stale - {VERSION})}"


# --- hai bản hướng dẫn song hành ---


def _sections(text: str) -> list[str]:
    return re.findall(r"^## (\d+[a-z]?)\.", text, re.MULTILINE)


def test_both_guides_have_the_same_sections():
    """Một bản hướng dẫn thiếu một mục nghĩa là người dùng ngôn ngữ đó không
    biết tính năng đó tồn tại."""
    assert _sections(EN) == _sections(VI)


def test_both_guides_document_the_2_0_features():
    assert "## 12c." in EN and "## 12c." in VI


def test_the_2_0_sections_have_the_same_number_of_subsections():
    def subsections(text: str) -> int:
        block = text.split("## 12c.")[1].split("\n## ")[0]
        return len(re.findall(r"^### ", block, re.MULTILINE))

    assert subsections(EN) == subsections(VI) >= 8


def test_neither_guide_is_written_in_the_wrong_language():
    """Bản tiếng Anh không được chứa câu tiếng Việt và ngược lại.

    Đây là lỗi đã xảy ra BA lần trong mã nguồn (thông báo lỗi xuất log, kết quả
    phân tích, lý do kiểm chứng). Tài liệu không được lặp lại nó.
    """
    vietnamese_only = re.compile(r"[ăâđêôơưĂÂĐÊÔƠƯ]|\b(và|của|không|được|những)\b")
    block = EN.split("## 12c.")[1].split("\n## ")[0]
    # Bỏ qua dòng trích dẫn giao diện và tên riêng.
    lines = [line for line in block.splitlines()
             if not line.startswith((">", "|", "`", "    "))]
    offenders = [line.strip()[:70] for line in lines if vietnamese_only.search(line)]
    assert offenders == [], f"câu tiếng Việt trong bản tiếng Anh: {offenders}"


# --- số liệu trong tài liệu khớp mã nguồn ---


def test_the_documented_entity_and_relation_counts_are_real():
    from shield.evidence.models import ENTITY_TYPES, RELATIONS

    assert f"{len(ENTITY_TYPES)} entity types" in EN
    assert f"{len(RELATIONS)} relations" in EN
    assert f"{len(ENTITY_TYPES)} loại thực thể" in VI
    assert f"{len(RELATIONS)} quan hệ" in VI


def test_the_documented_calibration_threshold_is_real():
    from shield.decision.calibration import MIN_SAMPLES

    assert f"at least {MIN_SAMPLES} labels" in EN
    assert f"đủ {MIN_SAMPLES} nhãn" in VI


def test_the_documented_redteam_numbers_are_real():
    corpus = json.loads(
        (ROOT / "shield/evals/datasets/redteam-corpus.json").read_text(encoding="utf-8"))
    assert f"{len(corpus['payloads'])} payloads" in README
    assert f"{len(corpus['surfaces'])} attacker-controlled surfaces" in README
    assert f"{len(corpus['behaviours'])} attack behaviours" in README


def test_the_documented_log_file_pattern_is_real():
    from shield.agent.log_export import FILE_PREFIX, FILE_SUFFIX

    pattern = f"{FILE_PREFIX}*{FILE_SUFFIX}"
    assert pattern in EN and pattern in VI


def test_the_documented_dropper_paths_are_real():
    from shield.security.mitre import DROPPER_PATH_PREFIXES

    for prefix in DROPPER_PATH_PREFIXES:
        bare = prefix.rstrip("/")
        assert bare in EN, f"{bare} không có trong bản tiếng Anh"
        assert bare in VI, f"{bare} không có trong bản tiếng Việt"


@_gate_only
def test_the_documented_hypothesis_states_are_real():
    from shield.ai.contracts import HYPOTHESIS_STATUS

    assert "confirmed" not in HYPOTHESIS_STATUS
    for state in ("unconfirmed", "supported", "contradicted"):
        assert state in HYPOTHESIS_STATUS
        assert state in EN


# --- bộ tài liệu không phình ra ---


# Tài liệu làm việc (kế hoạch, báo cáo gate) KHÔNG thuộc bộ tài liệu người dùng.
# Chúng sống ở gốc repo, có vòng đời riêng, và không bị luật "năm file" ràng
# buộc — luật đó tồn tại để `docs/` không phình ra, không phải để cấm ghi kế
# hoạch. Chỉ `docs/` mới bị đóng kín hoàn toàn.
WORKING_DOC_PREFIXES = ("KE-HOACH", "Shield_Upgrade", "RELEASE_GATE_REPORT")


@_internal_only
def test_the_documentation_set_stays_small():
    """Năm file, không hơn. Tài liệu thứ sáu là tài liệu không ai cập nhật."""
    allowed = {"README.md", "docs/USER_GUIDE.md", "docs/HUONG_DAN_SU_DUNG.md",
               "docs/ARCHITECTURE.md", "docs/PROBE.md"}
    found = {str(path.relative_to(ROOT)) for path in ROOT.glob("*.md")}
    found |= {str(path.relative_to(ROOT)) for path in (ROOT / "docs").glob("*.md")}
    working = {p for p in found
               if "/" not in p and p.startswith(WORKING_DOC_PREFIXES)}
    extra = found - allowed - working
    assert extra == set(), f"tài liệu ngoài bộ đã thống nhất: {sorted(extra)}"


@_internal_only
def test_the_user_facing_docs_directory_stays_closed():
    """Miễn trừ ở trên chỉ áp dụng cho gốc repo. `docs/` vẫn đúng bốn file."""
    found = {str(path.relative_to(ROOT)) for path in (ROOT / "docs").glob("*.md")}
    assert found == {"docs/USER_GUIDE.md", "docs/HUONG_DAN_SU_DUNG.md",
                     "docs/ARCHITECTURE.md", "docs/PROBE.md"}


# --- kiến trúc và báo cáo gate phải khớp mã nguồn ---


def test_the_architecture_covers_every_2_0_package():
    """Người đọc kiến trúc phải thấy hệ thống đang chạy, không phải một hệ
    thống cũ hơn năm phase."""
    for package in ("shield/evidence", "shield/ai", "shield/decision",
                    "shield/response", "shield/evals"):
        assert package in ARCH, f"{package} chưa được mô tả"


def test_the_documented_state_count_is_real():
    from shield.response.jobs import JobState

    assert f"{len(JobState.ALL)}-state machine" in ARCH


def test_the_documented_adapters_match_the_code():
    from shield.response.adapters.isolate_endpoint import IsolateEndpointAdapter
    from shield.response.adapters.rate_limit import RateLimitAdapter
    from shield.response.adapters.snapshot import SnapshotAdapter
    from shield.response.adapters.temporary_block import TemporaryBlockAdapter

    for cls in (SnapshotAdapter, TemporaryBlockAdapter, RateLimitAdapter,
                IsolateEndpointAdapter):
        assert f"`{cls.action}`" in ARCH, cls.action


def test_the_documented_calibration_floor_matches_the_code():
    from shield.decision.calibration import MIN_SAMPLES

    assert f"below {MIN_SAMPLES} labels" in ARCH


def test_the_documented_kill_switch_names_are_real():
    from shield.ai.capability import KILL_SWITCH_ENV
    from shield.response.executor import RESPONSE_KILL_SWITCH_ENV

    assert KILL_SWITCH_ENV in ARCH and RESPONSE_KILL_SWITCH_ENV in ARCH


@_gate_only
def test_the_release_report_covers_the_current_source():
    """Báo cáo phải gắn một commit, và KHÔNG mã nguồn nào được đổi từ đó tới nay.

    Bất biến không thể là "gắn đúng HEAD": một báo cáo không tự ghi được mã băm
    của chính commit chứa nó — sửa báo cáo là đổi hash, và đuổi theo mãi không
    tới. Điều thật sự đáng đảm bảo là báo cáo còn NÓI ĐÚNG về mã đang chạy: sửa
    tài liệu sau đó thì không sao, sửa `shield/` hay `probe/` thì phải chạy lại
    gate.
    """
    import subprocess

    match = re.search(r"\*\*Commit:\*\* `([0-9a-f]{40})`", GATE)
    assert match, "báo cáo không ghi commit"
    pinned = match.group(1)

    exists = subprocess.run(["git", "cat-file", "-e", pinned], cwd=ROOT,
                            capture_output=True)
    if exists.returncode != 0:
        pytest.skip("commit trong báo cáo không có trong repo này")

    changed = subprocess.run(
        ["git", "diff", "--name-only", f"{pinned}..HEAD", "--", "shield", "probe"],
        cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert changed == [], (
        f"mã nguồn đã đổi sau commit {pinned[:8]} mà báo cáo gate chưa chạy lại: "
        f"{changed[:5]}")


@_gate_only
def test_the_release_report_test_count_matches_reality():
    import subprocess

    import sys

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"], cwd=ROOT,
        capture_output=True, text=True)
    match = re.search(r"(\d+) tests? collected", result.stdout)
    if not match:
        pytest.skip("không đếm được số test")
    collected = int(match.group(1))
    claimed = re.search(r"(\d+) test thu được", GATE)
    assert claimed, "báo cáo không ghi số test thu được"
    # So với số THU ĐƯỢC, không phải số chạy: test cần root vẫn được thu, chỉ
    # bị bỏ qua. Trước đây báo cáo ghi "test không cần quyền" rồi so với số thu
    # được — hai đại lượng khác nhau, và chênh lệch bị nuốt bởi dung sai 20.
    assert abs(int(claimed.group(1)) - collected) <= 5, \
        f"báo cáo nói {claimed.group(1)} test, thực tế thu được {collected}"


# --- một sản phẩm, một số phiên bản ---


def test_every_place_that_states_a_version_states_the_same_one():
    """`shield/__init__.py` từng ghi "1.1.0rc1" trong khi `pyproject.toml` ghi
    "2.0.0a1" — hai con số cho cùng một sản phẩm. Giao diện đọc file thứ nhất,
    nên nó hiển thị "ver 1.1 RC" suốt cả hai vòng phát hành 2.0, và người dùng
    nhìn vào app thấy một phiên bản không tồn tại.

    Cùng một kiểu hỏng với hai bộ luật che bí mật và hai bảng thứ hạng severity:
    hai định nghĩa cho một khái niệm là hai câu trả lời cho cùng một câu hỏi.
    """
    from shield import __version__

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert declared, "pyproject.toml không khai version"
    assert declared.group(1) == __version__, (
        f'pyproject.toml nói {declared.group(1)!r}, shield/__init__.py nói {__version__!r}')

    for relative in ("README.md", "docs/USER_GUIDE.md", "docs/HUONG_DAN_SU_DUNG.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert __version__ in text, f"{relative} không nhắc phiên bản hiện tại"
        stale = re.findall(r"\b\d+\.\d+\.\d+(?:a|b|rc)\d+\b", text)
        wrong = sorted({v for v in stale
                        if v != __version__ and not v.startswith("1.1.0")})
        assert wrong == [], f"{relative} còn nhắc phiên bản cũ: {wrong}"


def test_the_display_version_matches_the_real_one():
    """Chuỗi hiển thị trên thanh tiêu đề phải nói cùng một phiên bản, chỉ ngắn
    hơn. "2.1 Alpha" cho 2.1.0a1 là được; "1.1 RC" thì không."""
    from shield import __display_version__, __version__

    major_minor = ".".join(__version__.split(".")[:2])
    assert __display_version__.startswith(major_minor), (
        f"{__display_version__!r} không khớp {__version__!r}")
