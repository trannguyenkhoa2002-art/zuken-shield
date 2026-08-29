"""Deterministic risk scoring.

No network or AI dependency is allowed here: the same alert plus the same
context must always receive the same score, making decisions explainable and
testable.

Risk = Severity x Confidence x Asset Value x Repetition x Threat Context
(KE-HOACH-SHIELD-1.1.md mục B1). The first two factors come from the alert
itself; the last three come from a `RiskContext` the caller reads out of the
store. Passing no context keeps the pre-1.1 behaviour exactly, so an alert
raised before the device is known still scores the same as it always did.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shield.common.models import Alert


# Asset value. `criticality` is already collected per device identity in
# `device_identities.criticality`; these are the only four legal values
# (store.update_device_metadata validates them).
ASSET_WEIGHT = {
    "Critical": 1.30,
    "Important": 1.15,
    "Normal": 1.00,
    "Low priority": 0.80,
}

# Threat context. Verdicts come from `threat_intel_cache` via security/intel.py.
THREAT_WEIGHT = {
    "malicious": 1.40,
    "suspicious": 1.15,
    "unknown": 1.00,
    "clean": 0.85,
}

# Repetition. Read from `alerts.count` — the dedupe counter that already
# exists. Bands rather than a curve so the result stays easy to explain to a
# human ("seen 12 times" -> x1.15) and easy to assert in a test.
REPETITION_BANDS = ((20, 1.25), (10, 1.15), (5, 1.08), (2, 1.03))

# A subject the operator explicitly trusted. Multiplicative so it scales with
# severity instead of flattening every alert by a fixed 15 points.
TRUSTED_WEIGHT = 0.60


@dataclass(frozen=True)
class RiskContext:
    """Everything outside the alert that legitimately changes its risk.

    Built by `Store.risk_context()`. Kept as a plain frozen dataclass so tests
    can construct one directly without a database.
    """

    asset_criticality: str = "Normal"
    trusted: bool = False
    repetition: int = 1
    threat_verdict: str = "unknown"
    threat_confidence: float = 0.0

    @staticmethod
    def from_dict(raw: dict | None) -> "RiskContext":
        if not raw:
            return RiskContext()
        criticality = str(raw.get("asset_criticality", "Normal"))
        verdict = str(raw.get("threat_verdict", "unknown"))
        return RiskContext(
            asset_criticality=criticality if criticality in ASSET_WEIGHT else "Normal",
            trusted=bool(raw.get("trusted", False)),
            repetition=max(1, int(raw.get("repetition", 1) or 1)),
            threat_verdict=verdict if verdict in THREAT_WEIGHT else "unknown",
            threat_confidence=max(0.0, min(1.0, float(raw.get("threat_confidence", 0.0) or 0.0))),
        )


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    # SỨC MẠNH BẰNG CHỨNG, không phải xác suất đúng.
    #
    # Trường này từng tên là `confidence` và được hiển thị y như một xác suất.
    # Người đọc thấy "confidence 0.90" và hiểu "90% khả năng đúng"; thực tế nó
    # chỉ có nghĩa "alert này có 5 mẩu bằng chứng và đã lặp lại". Mục 3.4 của
    # kế hoạch 2.0 cấm đúng chuyện đó.
    #
    # Độ chính xác THẬT của một detector nằm ở `shield/decision/calibration.py`
    # và chỉ tồn tại khi có người dán nhãn. Hai con số này không thay thế nhau.
    evidence_strength: float
    reasons: tuple[str, ...]
    factors: dict = field(default_factory=dict)
    # Độ chính xác đã hiệu chuẩn của detector này, hoặc None nếu chưa đủ mẫu.
    # None nghĩa là KHÔNG BIẾT — không phải 0, và cũng không phải 0.5.
    detector_precision: float | None = None

    @property
    def confidence(self) -> float:
        """Tên cũ, giữ lại để mã hiện có không đổi cùng lúc với ngữ nghĩa.

        Đổi tên trường VÀ đổi ý nghĩa trong cùng một lượt là cách chắc chắn để
        không ai biết chỗ nào đã sửa. Tên này sẽ biến mất khi UI và Alert đã
        chuyển hết sang `evidence_strength`.
        """
        return self.evidence_strength


def repetition_weight(count: int) -> float:
    for threshold, weight in REPETITION_BANDS:
        if count >= threshold:
            return weight
    return 1.0


class RiskScorer:
    _BASE = {"info": 15, "warning": 50, "critical": 80}
    _HIGH_SIGNAL = ("MITM", "BRUTEFORCE", "TARPIT", "MALWARE", "INTEGRITY")

    def __init__(self, calibration=None) -> None:
        # `calibration` là tuỳ chọn để scoring vẫn test được mà không cần
        # database, và để một lỗi ở bảng hiệu chuẩn không bao giờ làm hỏng
        # việc chấm điểm.
        self.calibration = calibration

    def assess(self, alert: Alert, context: RiskContext | None = None) -> RiskAssessment:
        context = context or RiskContext()

        # --- Severity: the base signal the detector itself asserted. ---
        base = self._BASE.get(alert.severity, 25)
        reasons = [f"severity:{alert.severity}"]
        evidence_count = len(alert.evidence)
        if evidence_count >= 3:
            base += 5
            reasons.append("evidence:rich")
        if any(token in alert.rule_id.upper() for token in self._HIGH_SIGNAL):
            base += 10
            reasons.append("rule:high-signal")

        # --- The four multiplicative factors. ---
        asset = ASSET_WEIGHT.get(context.asset_criticality, 1.0)
        if asset != 1.0:
            reasons.append(f"asset:{context.asset_criticality}")

        repetition = repetition_weight(context.repetition)
        if repetition != 1.0:
            reasons.append(f"repetition:{context.repetition}x")

        threat = THREAT_WEIGHT.get(context.threat_verdict, 1.0)
        if threat != 1.0:
            reasons.append(f"threat-intel:{context.threat_verdict}")

        # Evidence-carried trust stays supported so detectors that already set
        # evidence["trusted"] keep working without touching the store.
        trusted = context.trusted or alert.evidence.get("trusted") is True
        trust_weight = TRUSTED_WEIGHT if trusted else 1.0
        if trusted:
            reasons.append("subject:trusted")

        score = base * asset * repetition * threat * trust_weight

        # --- Sức mạnh bằng chứng: bằng chứng phong phú tới đâu, tách hẳn
        # khỏi mức độ nghiêm trọng VÀ khỏi độ chính xác của detector. ---
        confidence = 0.55 + min(evidence_count, 5) * 0.07
        if context.repetition >= 5:
            # Something seen repeatedly is less likely to be a one-off glitch.
            confidence += 0.05
            reasons.append("evidence:repeated-observation")
        if context.threat_verdict in {"malicious", "suspicious"}:
            confidence += 0.10 * context.threat_confidence
            reasons.append("evidence:intel-corroborated")
        confidence = min(0.98, confidence)

        factors = {
            "base": base,
            "asset": asset,
            "repetition": repetition,
            "threat": threat,
            "trust": trust_weight,
        }
        return RiskAssessment(
            max(0, min(100, round(score))), round(confidence, 4), tuple(reasons), factors,
            detector_precision=self.precision_for(alert.rule_id),
        )

    def precision_for(self, rule_id: str) -> float | None:
        """Độ chính xác đã hiệu chuẩn, hoặc None. Mặc định KHÔNG BIẾT.

        `RiskScorer` cố ý không tự mở database: nó là hàm thuần và phải giữ
        được tính đó. Chỗ gọi nào có bảng hiệu chuẩn thì truyền một
        `calibration` vào constructor.
        """
        if self.calibration is None:
            return None
        try:
            return self.calibration.precision_for(rule_id)
        except Exception:  # noqa: BLE001 — thiếu hiệu chuẩn không được làm hỏng scoring
            return None
