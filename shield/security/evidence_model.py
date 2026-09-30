"""Evidence Confidence: Shield chắc chắn tới đâu, và còn THIẾU bằng chứng gì.

Tách hẳn khỏi Behavior Risk (`scoring.py`):

- **Behavior Risk** — hành vi này nguy hiểm tới mức nào NẾU nó đúng.
- **Evidence Confidence** — bằng chứng Shield đang có ủng hộ kết luận đó tới
  đâu, trên thang 0..100.

Ví dụ: một brute force SSH có Risk 82 nhưng Confidence 60 vì chưa thấy đăng
nhập thành công hay phiên đặc quyền nào từ nguồn đó. Người phân tích cần thấy
CẢ HAI con số và danh sách còn thiếu — một con số gộp che mất đúng điều họ cần
biết để quyết định bước tiếp theo.

Mô hình là KHAI BÁO và TẤT ĐỊNH: mỗi rule có một danh sách bằng chứng mong đợi
kèm trọng số; điểm là tỷ lệ trọng số đã quan sát được. Không có model, không có
xác suất. Rule chưa có mô hình KHÔNG được bịa danh sách thiếu — nó mang
`basis="generic"` và điểm dựa trên độ phong phú bằng chứng cũ, ghi rõ là vậy.

Mô hình này KHÔNG xác nhận tấn công. Không mức Confidence nào biến một alert
thành "confirmed"; việc đó là của bằng chứng + policy + con người
(KE-HOACH: AI và điểm số chỉ hỗ trợ lập luận).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shield.common.models import Alert


@dataclass(frozen=True)
class ExpectedEvidence:
    fact: str
    weight: int
    label_en: str
    label_vi: str


@dataclass(frozen=True)
class EvidenceConfidence:
    score: int                       # 0..100
    basis: str                       # "model:<RULE>" | "generic"
    observed: tuple[str, ...] = ()   # fact ids đã thấy
    missing: tuple[str, ...] = ()    # fact ids mong đợi mà chưa thấy
    labels: dict = field(default_factory=dict)  # fact -> {"en":..., "vi":...}

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "basis": self.basis,
            "observed": list(self.observed),
            "missing": list(self.missing),
            "labels": self.labels,
        }


def _e(fact: str, weight: int, en: str, vi: str) -> ExpectedEvidence:
    return ExpectedEvidence(fact, weight, en, vi)


_SOURCE_IDENTIFIED = _e("source_identified", 10, "Source address identified", "Đã xác định địa chỉ nguồn")
_SOURCE_UNTRUSTED = _e("source_untrusted", 10, "Source is not a trusted device", "Nguồn không phải thiết bị tin cậy")

# Tổng trọng số mỗi mô hình là 100, để điểm đọc được ngay: "60/100" nghĩa là
# đã thấy các mẩu cộng lại 60 điểm.
EVIDENCE_MODELS: dict[str, tuple[ExpectedEvidence, ...]] = {
    "LOCAL_SSH_BRUTEFORCE": (
        _e("threshold_exceeded", 25, "Failed logins above threshold", "Số lần đăng nhập sai vượt ngưỡng"),
        _SOURCE_IDENTIFIED,
        _SOURCE_UNTRUSTED,
        _e("sustained", 15, "Sustained or repeated attempts", "Thử liên tục hoặc lặp lại"),
        _e("login_succeeded_from_source", 25, "Successful login from the same source",
           "Đăng nhập thành công từ cùng nguồn"),
        _e("privileged_session_from_source", 15, "Privileged (root) session from the same source",
           "Phiên đặc quyền (root) từ cùng nguồn"),
    ),
    "SCAN_PORTSCAN": (
        _e("many_ports", 25, "Ten or more distinct ports probed", "Dò từ 10 cổng khác nhau trở lên"),
        _SOURCE_IDENTIFIED,
        _SOURCE_UNTRUSTED,
        _e("handshake_observed", 15, "Handshake completed on a probed port",
           "Có bắt tay hoàn tất trên cổng bị dò"),
        _e("packet_level_capture", 15, "Seen at packet level, not only in aggregates",
           "Thấy ở mức gói tin, không chỉ số liệu gộp"),
        _e("followed_by_auth_attempts", 25, "Authentication attempts from the same source after the scan",
           "Có thử đăng nhập từ cùng nguồn sau lượt dò"),
    ),
    "MITM_GATEWAY_MAC_CHANGED": (
        _e("baseline_mismatch", 30, "Gateway MAC differs from the recorded baseline",
           "MAC gateway khác baseline đã ghi"),
        _e("observed_mac_identified", 10, "The new MAC is recorded", "Đã ghi lại MAC mới"),
        _e("repeated_observation", 20, "Seen more than once", "Thấy lặp lại nhiều lần"),
        _e("mac_belongs_to_other_host", 20, "The new MAC is a known LAN host with another IP",
           "MAC mới là một máy LAN đã biết với IP khác"),
        _e("dns_changed_nearby", 20, "DNS resolver changed around the same time",
           "Resolver DNS đổi trong cùng khoảng thời gian"),
    ),
    "DNS_RESOLVER_CHANGED": (
        _e("resolver_differs", 35, "Resolver differs from the learned baseline",
           "Resolver khác baseline đã học"),
        _e("repeated_observation", 20, "Seen more than once", "Thấy lặp lại nhiều lần"),
        _e("rogue_dhcp_nearby", 25, "An unknown DHCP server appeared around the same time",
           "Có DHCP server lạ xuất hiện cùng khoảng thời gian"),
        _e("gateway_tampering_nearby", 20, "Gateway MAC change or ARP conflict around the same time",
           "Đổi MAC gateway hoặc xung đột ARP cùng khoảng thời gian"),
    ),
    "MITM_ROGUE_DHCP": (
        _e("server_differs", 35, "DHCP server differs from the learned one", "DHCP server khác server đã học"),
        _SOURCE_IDENTIFIED,
        _e("repeated_observation", 20, "Seen more than once", "Thấy lặp lại nhiều lần"),
        _e("dns_changed_nearby", 20, "DNS resolver changed around the same time",
           "Resolver DNS đổi trong cùng khoảng thời gian"),
        _e("rogue_server_on_lan", 15, "The rogue server is a known LAN device",
           "Server lạ là một thiết bị LAN đã biết"),
    ),
    "MITM_ARP_CONFLICT": (
        _e("multiple_claimants", 35, "Two or more MACs claim the same IP", "Từ hai MAC trở lên cùng claim một IP"),
        _e("repeated_observation", 25, "Seen more than once", "Thấy lặp lại nhiều lần"),
        _e("gateway_involved", 25, "The contested IP is the gateway", "IP bị tranh chấp là gateway"),
        _e("dns_changed_nearby", 15, "DNS resolver changed around the same time",
           "Resolver DNS đổi trong cùng khoảng thời gian"),
    ),
}

# Những fact chỉ đọc được từ database (lịch sử), không từ chính alert. Chỗ gọi
# có store tra chúng qua `Store.evidence_facts`; `RiskScorer` vẫn là hàm thuần.
STORE_FACTS = frozenset({
    "login_succeeded_from_source", "privileged_session_from_source",
    "followed_by_auth_attempts", "mac_belongs_to_other_host",
    "dns_changed_nearby", "gateway_involved",
    "rogue_dhcp_nearby", "gateway_tampering_nearby", "rogue_server_on_lan",
})


def model_for(rule_id: str) -> tuple[ExpectedEvidence, ...] | None:
    return EVIDENCE_MODELS.get(rule_id)


def alert_facts(alert: Alert, *, trusted: bool, repetition: int) -> set[str]:
    """Fact suy ra được từ chính alert và ngữ cảnh chấm điểm, không cần DB."""
    ev = alert.evidence or {}
    facts: set[str] = set()
    source = ev.get("src_ip") or ev.get("source_ip") or ev.get("rogue_dhcp")
    if source:
        facts.add("source_identified")
        if not trusted:
            facts.add("source_untrusted")
    if repetition >= 2:
        facts.add("repeated_observation")

    rule = alert.rule_id
    if rule == "LOCAL_SSH_BRUTEFORCE":
        fails = _int(ev.get("fail_count"))
        if fails >= 5:
            facts.add("threshold_exceeded")
        if fails >= 20 or repetition >= 2:
            facts.add("sustained")
    elif rule == "SCAN_PORTSCAN":
        ports = ev.get("ports") or []
        if isinstance(ports, list) and len(ports) >= 10:
            facts.add("many_ports")
        if ev.get("acked_ports_matched"):
            facts.add("handshake_observed")
        if ev.get("ack_source") == "packet":
            facts.add("packet_level_capture")
    elif rule == "MITM_GATEWAY_MAC_CHANGED":
        baseline, observed = str(ev.get("baseline_mac", "")).lower(), str(ev.get("observed_mac", "")).lower()
        if baseline and observed and baseline != observed:
            facts.add("baseline_mismatch")
        if observed:
            facts.add("observed_mac_identified")
    elif rule == "DNS_RESOLVER_CHANGED":
        if str(ev.get("baseline", "")) and str(ev.get("current", "")) and ev.get("baseline") != ev.get("current"):
            facts.add("resolver_differs")
    elif rule == "MITM_ROGUE_DHCP":
        if ev.get("known_dhcp") and ev.get("rogue_dhcp") and ev.get("known_dhcp") != ev.get("rogue_dhcp"):
            facts.add("server_differs")
    elif rule == "MITM_ARP_CONFLICT":
        macs = ev.get("macs") or []
        if isinstance(macs, list) and len(set(macs)) >= 2:
            facts.add("multiple_claimants")
    return facts


def evaluate(alert: Alert, facts: set[str], generic_strength: float) -> EvidenceConfidence:
    """Điểm Confidence cho một alert, từ tập fact đã quan sát.

    `generic_strength` (0..1) là độ phong phú bằng chứng kiểu cũ — CHỈ dùng khi
    rule chưa có mô hình, và khi đó `basis="generic"` nói rõ điều đó.
    """
    model = model_for(alert.rule_id)
    if model is None:
        return EvidenceConfidence(max(0, min(100, round(generic_strength * 100))), "generic")
    total = sum(item.weight for item in model)
    observed = tuple(item.fact for item in model if item.fact in facts)
    missing = tuple(item.fact for item in model if item.fact not in facts)
    gained = sum(item.weight for item in model if item.fact in facts)
    labels = {item.fact: {"en": item.label_en, "vi": item.label_vi} for item in model}
    return EvidenceConfidence(round(100 * gained / total), f"model:{alert.rule_id}",
                              observed, missing, labels)


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


_TEXT = {
    "risk": {"en": "Behavior risk", "vi": "Rủi ro hành vi"},
    "confidence": {"en": "Evidence confidence", "vi": "Độ tin cậy bằng chứng"},
    "observed": {"en": "Observed", "vi": "Đã thấy"},
    "missing": {"en": "Missing evidence", "vi": "Còn thiếu bằng chứng"},
    "generic": {"en": "generic estimate — no evidence model for this rule yet",
                "vi": "ước lượng chung — rule này chưa có mô hình bằng chứng"},
    "not_assessed": {"en": "not assessed", "vi": "chưa đánh giá"},
    "none": {"en": "none", "vi": "không có"},
}


def confidence_cell(alert: dict) -> str:
    """Ô bảng: "60/100", "57/100*" (generic) hoặc "—" (chưa đánh giá)."""
    score = int(alert.get("evidence_confidence", -1))
    if score < 0:
        return "—"
    generic = (alert.get("evidence_assessment") or {}).get("basis", "generic") == "generic"
    return f"{score}/100{'*' if generic else ''}"


def describe(alert: dict, lang: str = "en") -> str:
    """Khối chữ Risk / Confidence / Observed / Missing cho hộp chi tiết alert."""
    lang = "vi" if lang == "vi" else "en"
    lines = [f"{_TEXT['risk'][lang]}: {int(alert.get('risk_score', 0))}/100"]
    score = int(alert.get("evidence_confidence", -1))
    assessment = alert.get("evidence_assessment") or {}
    if score < 0:
        lines.append(f"{_TEXT['confidence'][lang]}: {_TEXT['not_assessed'][lang]}")
        return "\n".join(lines)
    if assessment.get("basis", "generic") == "generic":
        lines.append(f"{_TEXT['confidence'][lang]}: {score}/100 ({_TEXT['generic'][lang]})")
        return "\n".join(lines)
    labels = assessment.get("labels") or {}

    def names(facts) -> str:
        shown = [str((labels.get(f) or {}).get(lang) or f) for f in facts or ()]
        return "; ".join(shown) if shown else _TEXT["none"][lang]

    lines.append(f"{_TEXT['confidence'][lang]}: {score}/100")
    lines.append(f"{_TEXT['observed'][lang]}: {names(assessment.get('observed'))}")
    lines.append(f"{_TEXT['missing'][lang]}: {names(assessment.get('missing'))}")
    return "\n".join(lines)


def fact_label(rule_id: str, fact: str, lang: str = "en") -> str:
    """Nhãn người đọc của một fact trong mô hình của rule; fact lạ trả lại id."""
    for item in EVIDENCE_MODELS.get(rule_id, ()):
        if item.fact == fact:
            return item.label_vi if lang == "vi" else item.label_en
    return fact
