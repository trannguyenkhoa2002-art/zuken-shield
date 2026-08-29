"""Chỉ MỘT nơi định nghĩa "cái gì là bí mật".

Lỗi này đã xảy ra hai lần:

- 2.0: `evidence/queries.py` và `ai/redaction.py` mỗi bên một bộ luật; bộ yếu
  hơn được dùng ở đúng chỗ nhật ký lời gọi tool, nên khoá AWS, token GitHub và
  token Slack lọt vào nhật ký.
- 3.0 (Phase 0): `security/analysis.py` vẫn giữ bộ luật riêng thứ ba — 5 tên
  khoá và một regex `bearer` — trong khi `LocalSummaryAnalyzer` chạy trên bản
  ghi thật.

Lần một sửa bằng cách gộp hai chỗ gọi. Sửa như vậy không giữ được: cái thứ ba
nằm ở package khác nên grep theo package không thấy. Lần này sửa bằng một bất
biến kiểm được: hàm che nào cũng phải lấy luật từ `shield/common/secrets.py`.

Đây là điều kiện dừng `secret redaction paths disagree` trong kế hoạch nâng cấp.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANONICAL = "shield/common/secrets.py"


def _shield_sources() -> list[Path]:
    return sorted(ROOT.glob("shield/**/*.py"))


def _imports_canonical(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "shield.common.secrets":
            return True
    return False


def test_every_redactor_takes_its_rules_from_the_canonical_module():
    """Được phép có nhiều hàm `redact` — mỗi đường có trần và ngữ cảnh riêng.
    KHÔNG được phép là một hàm `redact` tự nghĩ ra luật của nó."""
    offenders = []
    for path in _shield_sources():
        relative = str(path.relative_to(ROOT))
        if relative == CANONICAL:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        defines = [
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("redact")
        ]
        if defines and not _imports_canonical(tree):
            offenders.append(f"{relative}: {defines}")
    assert offenders == [], (
        "những chỗ này tự định nghĩa luật che riêng: " + "; ".join(offenders)
    )


def test_no_module_hardcodes_its_own_redaction_marker():
    """Một dấu che thứ hai là dấu hiệu của một bộ luật thứ hai."""
    offenders = []
    for path in _shield_sources():
        relative = str(path.relative_to(ROOT))
        if relative == CANONICAL:
            continue
        text = path.read_text(encoding="utf-8")
        if "[REDACTED]" in text:
            offenders.append(relative)
    assert offenders == [], f"dấu che viết cứng ở: {offenders}"
