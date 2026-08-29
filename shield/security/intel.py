"""Privacy-conscious threat-intelligence provider abstraction."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from shield.security.supply_chain import verify_detached_signature

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def normalize_indicator(value: str) -> tuple[str, str]:
    value = value.strip()
    if value.lower().startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("unsupported or invalid threat indicator")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        return "url", urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if _HASH_RE.fullmatch(value):
        return "hash", value.lower()
    domain = value.rstrip(".").lower()
    if _DOMAIN_RE.fullmatch(domain):
        return "domain", domain
    raise ValueError("unsupported or invalid threat indicator")


@dataclass(frozen=True)
class IntelResult:
    provider: str
    verdict: str  # clean | suspicious | malicious | unknown
    confidence: float
    details: dict
    cached: bool = False
    # Nguồn ngoài CHỈ đối chứng — nó không bao giờ một mình xác nhận một máy
    # đã bị chiếm (mục 5.3). Đặt mặc định True để một provider mới viết ra sau
    # này phải nói tường minh nếu nó muốn khác, thay vì mặc nhiên được tin.
    corroboration_only: bool = True


class IntelProvider(Protocol):
    name: str
    async def lookup(self, indicator_type: str, indicator: str) -> IntelResult: ...


class StaticIntelProvider:
    """Offline provider suitable for organization-managed deny lists."""
    name = "static"

    def __init__(self, entries: dict[tuple[str, str], str] | None = None) -> None:
        self.entries = entries or {}

    async def lookup(self, indicator_type: str, indicator: str) -> IntelResult:
        verdict = self.entries.get((indicator_type, indicator), "unknown")
        return IntelResult(self.name, verdict, 1.0 if verdict != "unknown" else 0.0, {"source": "local"})


class SignedOfflineFeedProvider(StaticIntelProvider):
    """Organization-managed JSON IOC feed with optional mandatory signature."""

    name = "signed-offline-feed"

    @classmethod
    def load(cls, path: Path, public_key: Path | None = None, signature: Path | None = None):
        if public_key is not None:
            if signature is None:
                raise ValueError("offline feed signature required")
            ok, message = verify_detached_signature(path, signature, public_key)
            if not ok:
                raise ValueError(message)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 1 or not isinstance(raw.get("indicators"), list):
            raise ValueError("invalid offline feed schema")
        entries = {}
        for item in raw["indicators"][:100_000]:
            indicator_type, indicator = normalize_indicator(str(item["value"]))
            verdict = str(item.get("verdict", "malicious"))
            if verdict not in {"clean", "suspicious", "malicious"}:
                raise ValueError("invalid offline feed verdict")
            entries[(indicator_type, indicator)] = verdict
        return cls(entries)


class KnowledgeFeedProvider:
    """Đọc chỉ dấu từ kho tri thức có nguồn gốc và đường thu hồi (mục 5.3).

    Khác `StaticIntelProvider` ở chỗ: mỗi câu trả lời mang theo tài liệu nào
    nói ra nó, tài liệu đó đã ký chưa, và nó thuộc bậc tin cậy nào. Một chỉ dấu
    không nói được nó đến từ đâu thì không dùng được để giải thích bất cứ điều gì.

    Tài liệu bị thu hồi biến mất khỏi kết quả NGAY, không cần khởi động lại.
    """

    name = "knowledge"

    def __init__(self, knowledge) -> None:
        self.knowledge = knowledge

    async def lookup(self, indicator_type: str, indicator: str) -> IntelResult:
        matches = self.knowledge.lookup(indicator_type, indicator)
        if not matches:
            return IntelResult(self.name, "unknown", 0.0, {"documents": []})
        trusted = [m for m in matches if m["trust_tier"] == "trusted"]
        # Bậc `untrusted` KHÔNG được quyết định verdict. Nó vẫn hiện ra trong
        # `details` để người điều tra thấy, nhưng nó không đổi kết luận — đó
        # chính là ranh giới mục 5.3 vẽ ra.
        deciding = trusted or []
        verdict = _strongest([m["verdict"] for m in deciding]) if deciding else "unknown"
        return IntelResult(
            self.name, verdict,
            1.0 if verdict != "unknown" else 0.0,
            {"documents": [
                {k: m[k] for k in ("doc_id", "source", "trust_tier", "signature_status",
                                   "verdict", "imported_ts")}
                for m in matches[:10]],
             "trusted_documents": len(trusted),
             "untrusted_documents": len(matches) - len(trusted)},
        )


def _strongest(verdicts) -> str:
    """Kết luận nặng nhất trong các tài liệu tin cậy.

    Nặng nhất chứ không phải mới nhất: nếu một nguồn nói `malicious` và một
    nguồn nói `clean`, câu trả lời an toàn là nêu ra cái đáng lo — và người
    điều tra thấy cả hai trong `details`.
    """
    order = {"malicious": 3, "suspicious": 2, "clean": 1}
    best = max(verdicts, key=lambda v: order.get(v, 0), default="unknown")
    return best if best in order else "unknown"


def stix_bundle_entries(bundle: dict) -> dict[tuple[str, str], str]:
    """Extract exact IPv4/IPv6, domain, URL and file hash STIX patterns."""
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("invalid STIX bundle")
    entries = {}
    pattern = re.compile(r"^\[(?:ipv4-addr|ipv6-addr|domain-name|url):value = '([^']+)'\]$|^\[file:hashes\.'SHA-256' = '([0-9A-Fa-f]{64})'\]$")
    for obj in bundle["objects"][:100_000]:
        if obj.get("type") != "indicator" or obj.get("revoked"):
            continue
        match = pattern.fullmatch(str(obj.get("pattern", "")))
        if not match:
            continue
        indicator_type, indicator = normalize_indicator(match.group(1) or match.group(2))
        entries[(indicator_type, indicator)] = "malicious"
    return entries


class TaxiiImportAdapter:
    """Opt-in adapter: caller supplies fetched STIX, so Shield uploads nothing."""

    name = "taxii-import"

    @staticmethod
    def from_stix_bundle(bundle: dict) -> StaticIntelProvider:
        return StaticIntelProvider(stix_bundle_entries(bundle))


class ThreatIntelService:
    def __init__(self, store, providers: list[IntelProvider], ttl_s: float = 3600, timeout_s: float = 3.0) -> None:
        self.store, self.providers = store, tuple(providers)
        self.ttl_s, self.timeout_s = ttl_s, timeout_s

    async def check(self, raw_indicator: str) -> list[IntelResult]:
        indicator_type, indicator = normalize_indicator(raw_indicator)
        results = []
        for provider in self.providers:
            cached = self.store.get_threat_intel_cache(indicator_type, indicator, provider.name)
            if cached:
                payload = cached["payload"]
                results.append(IntelResult(provider.name, cached["verdict"], float(payload.get("confidence", 0)), payload.get("details", {}), True))
                continue
            try:
                result = await asyncio.wait_for(provider.lookup(indicator_type, indicator), self.timeout_s)
            except (TimeoutError, OSError):
                result = IntelResult(provider.name, "unknown", 0.0, {"error": "provider timeout"})
            if result.verdict not in {"clean", "suspicious", "malicious", "unknown"}:
                result = IntelResult(provider.name, "unknown", 0.0, {"error": "invalid provider verdict"})
            self.store.put_threat_intel_cache(indicator_type, indicator, provider.name, result.verdict, {"confidence": result.confidence, "details": result.details}, self.ttl_s)
            results.append(result)
        return results
