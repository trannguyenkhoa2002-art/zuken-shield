"""Zuken Shield endpoint and local-network defense platform."""

# NGUỒN DUY NHẤT của số phiên bản. `pyproject.toml` phải khớp, và
# `tests/test_docs_consistency.py` giữ điều đó.
#
# Trước đây file này ghi "1.1.0rc1" trong khi `pyproject.toml` ghi "2.0.0a1":
# hai con số cho cùng một sản phẩm. Giao diện đọc file này nên nó hiển thị
# "ver 1.1 RC" suốt cả hai vòng phát hành 2.0 — người dùng nhìn vào app và
# thấy một phiên bản không tồn tại.
__version__ = "3.0.0a11"


def _display(version: str) -> str:
    """"3.0.0a4" -> "3.0 Alpha 4". SUY RA từ __version__, không gõ tay: bản
    3.0.0a4 cài trên máy thật (29/09/2026) vẫn hiện "ver 3.0 Alpha 2" vì chuỗi
    hiển thị bị quên khi nâng số."""
    import re

    match = re.fullmatch(r"(\d+)\.(\d+)\.\d+(?:(a|b|rc)(\d+))?", version)
    if not match:
        return version
    major, minor, stage, number = match.groups()
    label = {"a": "Alpha", "b": "Beta", "rc": "RC"}.get(stage or "", "")
    return f"{major}.{minor} {label} {number}".strip() if label else f"{major}.{minor}"


__display_version__ = _display(__version__)
__creator__ = "Zuken"
__product_name__ = "Zuken Shield"
