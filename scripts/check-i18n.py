#!/usr/bin/env python3
"""Kiểm bản dịch giao diện: khoá thiếu, bản dịch trùng, chữ viết cứng không qua t().

    python scripts/check-i18n.py            # báo cáo
    python scripts/check-i18n.py --strict   # thoát 1 nếu có khoá thiếu hoặc chữ viết cứng
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from shield.ui.i18n import STRINGS  # noqa: E402

UI_FILES = sorted((ROOT / "shield" / "ui").glob("*.py"))
# Hàm Qt nhận chữ HIỂN THỊ cho người dùng.
DISPLAY_CALLS = {"setText", "setWindowTitle", "setPlaceholderText", "setToolTip", "addItem",
                 "setTitle", "setHorizontalHeaderLabels", "information", "warning", "question",
                 "critical", "showMessage", "addTab", "setTabText"}
DISPLAY_CTORS = {"QLabel", "QPushButton", "QCheckBox", "QGroupBox", "QAction", "QToolButton",
                 "ElidedLabel", "QListWidgetItem", "QTableWidgetItem", "QRadioButton"}
LETTERS = re.compile(r"[A-Za-zÀ-ỹ]{2,}")
# Chữ không cần dịch: ký hiệu, đơn vị, tên kỹ thuật, dấu phân cách.
# Tên ngôn ngữ luôn viết bằng chính ngôn ngữ đó; định dạng giờ; hậu tố tên cửa sổ.
ALLOWED_LITERALS = {"OK", "—", "1h", "24h", "7d", "…", "English", "Tiếng Việt", "HH:MM", "— Shield"}


def used_keys() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in UI_FILES:
        if path.name == "i18n.py":      # chỉ chứa định nghĩa và ví dụ trong docstring
            continue
        for match in re.finditer(r'\bt\(\s*"([a-z0-9_.]+)"', path.read_text(encoding="utf-8")):
            found.setdefault(match.group(1), []).append(path.name)
    return found


def dynamic_keys() -> list[tuple[str, str]]:
    out = []
    for path in UI_FILES:
        for match in re.finditer(r'\bt\(\s*f"([a-z0-9_.]+)\{', path.read_text(encoding="utf-8")):
            out.append((match.group(1), path.name))
    return out


def hardcoded() -> list[tuple[str, int, str]]:
    problems = []
    for path in UI_FILES:
        if path.name == "i18n.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name not in DISPLAY_CALLS and name not in DISPLAY_CTORS:
                continue
            # addItem(nhãn, dữ_liệu): chỉ tham số ĐẦU là chữ hiển thị.
            args = node.args[:1] if name == "addItem" else node.args
            for arg in args:
                values = []
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    values = [arg.value]
                elif isinstance(arg, ast.JoinedStr):
                    values = [part.value for part in arg.values
                              if isinstance(part, ast.Constant) and isinstance(part.value, str)]
                for value in values:
                    if value.strip() in ALLOWED_LITERALS or not LETTERS.search(value):
                        continue
                    problems.append((path.name, node.lineno, value.strip()[:70]))
    return problems


def main() -> int:
    strict = "--strict" in sys.argv
    used = used_keys()
    missing = sorted(k for k in used if k not in STRINGS)
    same = sorted(k for k, (vi, en) in STRINGS.items() if vi == en and LETTERS.search(en))
    empty = sorted(k for k, (vi, en) in STRINGS.items() if not vi.strip() or not en.strip())
    placeholder_mismatch = sorted(
        k for k, (vi, en) in STRINGS.items()
        if set(re.findall(r"\{(\w+)\}", vi)) != set(re.findall(r"\{(\w+)\}", en)))
    literals = hardcoded()
    prefixes = sorted({(p, f) for p, f in dynamic_keys()})
    print(f"keys used: {len(used)}  defined: {len(STRINGS)}")
    print(f"\nMISSING keys ({len(missing)}):")
    for key in missing:
        print(f"  {key}  <- {', '.join(sorted(set(used[key])))}")
    print(f"\nEMPTY translations ({len(empty)}): {empty}")
    print(f"\nPLACEHOLDER mismatch vi/en ({len(placeholder_mismatch)}): {placeholder_mismatch}")
    print(f"\nHARDCODED display text ({len(literals)}):")
    for name, line, value in literals:
        print(f"  {name}:{line}  {value!r}")
    print(f"\nIDENTICAL vi == en ({len(same)}) — kiểm tay, nhiều mục là tên riêng/thuật ngữ:")
    print("  " + ", ".join(same))
    print(f"\nDYNAMIC key prefixes ({len(prefixes)}) — mỗi giá trị có thể có phải có khoá:")
    for prefix, name in prefixes:
        defined = sorted(k[len(prefix):] for k in STRINGS if k.startswith(prefix))
        print(f"  {prefix}*  ({name}) defined suffixes: {defined}")
    failed = bool(missing or empty or placeholder_mismatch or (strict and literals))
    return 1 if (strict and failed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
