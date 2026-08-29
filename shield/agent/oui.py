"""Tra vendor từ MAC — dò file OUI hệ thống trước, fallback sang thư viện `manuf`.

Thứ tự ưu tiên (KE-HOACH-SHIELD.md mục 1.4 + README "Ubuntu vs Kali"):
1. /usr/share/ieee-data/oui.txt — có sẵn trên Kali, trên Ubuntu cần
   `apt install ieee-data` (install.sh tự cài, có thể không có gói tuỳ bản).
2. /usr/share/nmap/nmap-mac-prefixes — thường có sẵn nếu đã cài nmap
   (bắt buộc phải có cho collector discovery), dữ liệu ít đầy đủ hơn oui.txt.
3. Thư viện `manuf` (pip, không phụ thuộc distro) — luôn hoạt động nhưng
   dữ liệu đóng gói cùng thư viện, có thể cũ hơn.

Nếu cả ba đều không có: trả về None, nơi gọi tự fallback sang vendor_hint
mà arp-scan/nmap tự in kèm trong output của chúng.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("shield.oui")

_OUI_TXT_CANDIDATES = ["/usr/share/ieee-data/oui.txt"]
_NMAP_PREFIX_CANDIDATES = ["/usr/share/nmap/nmap-mac-prefixes"]

_cache: dict[str, str] = {}
_manuf_parser = None
_loaded = False


def _normalize_prefix(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "")[:6]


def _load_oui_txt(path: Path) -> None:
    # Định dạng IEEE: "AA-BB-CC   (hex)\t\tVendor Name"
    for line in path.read_text(errors="ignore").splitlines():
        if "(hex)" not in line:
            continue
        prefix_part, _, vendor_part = line.partition("(hex)")
        prefix = prefix_part.strip().replace("-", "")
        vendor = vendor_part.strip()
        if len(prefix) == 6:
            _cache[prefix] = vendor


def _load_nmap_prefixes(path: Path) -> None:
    # Định dạng nmap: "AABBCC Vendor Name"
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        prefix, _, vendor = line.partition(" ")
        if len(prefix) == 6:
            _cache.setdefault(prefix.upper(), vendor.strip())


def _ensure_loaded() -> None:
    global _loaded, _manuf_parser
    if _loaded:
        return
    _loaded = True

    for candidate in _OUI_TXT_CANDIDATES:
        path = Path(candidate)
        if path.exists():
            try:
                _load_oui_txt(path)
                logger.info("Tra vendor MAC từ %s (%d entry)", path, len(_cache))
                return
            except OSError:
                logger.warning("Không đọc được %s", path)

    for candidate in _NMAP_PREFIX_CANDIDATES:
        path = Path(candidate)
        if path.exists():
            try:
                _load_nmap_prefixes(path)
                logger.info("Tra vendor MAC từ %s (%d entry)", path, len(_cache))
                return
            except OSError:
                logger.warning("Không đọc được %s", path)

    try:
        from manuf import manuf

        _manuf_parser = manuf.MacParser()
        logger.info("Không có file OUI hệ thống — dùng thư viện manuf (pip)")
    except ImportError:
        logger.warning(
            "Không có file OUI hệ thống và chưa cài manuf — vendor sẽ dựa vào "
            "vendor_hint của arp-scan/nmap, hoặc 'không rõ'"
        )


def lookup_vendor(mac: str) -> str | None:
    _ensure_loaded()
    if _cache:
        vendor = _cache.get(_normalize_prefix(mac))
        if vendor:
            return vendor
    if _manuf_parser is not None:
        try:
            return _manuf_parser.get_manuf(mac)
        except Exception:
            return None
    return None
