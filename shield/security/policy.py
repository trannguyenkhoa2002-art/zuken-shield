"""Quyết định phản ứng tự động — tất định, có cấu hình ký, mặc định audit-only.

KE-HOACH-SHIELD-2.0.md mục 0.3.

Ba bất biến của file này:

1. **Mặc định khởi động là `audit_only`.** Không có biến môi trường nào, không
   có file cấu hình không ký nào bật được auto-response. Muốn bật phải có cấu
   hình đã ký bằng khoá vận hành.
2. **Phase 0 không tự thực thi.** Policy chỉ sinh `ResponseProposal` — một đề
   xuất có ID, có TTL, có evidence, có lý do. Ai đó phải duyệt. Việc nối
   proposal vào hàng đợi thực thi là Phase 4, sau khi có apply/verify/rollback.
3. **Không đọc policy từ text do model sinh.** `PolicyConfig` chỉ đến từ file
   JSON đã ký. `action` chỉ được lấy từ allowlist cứng trong mã nguồn — model
   (hay bất cứ nguồn không tin cậy nào) nhiều nhất chỉ đề xuất được một ID
   nằm sẵn trong allowlist đó, không bao giờ đặt ra được ID mới.
"""

from __future__ import annotations

import json
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shield.decision.models import DecisionOutcome

# Allowlist CỨNG, nằm trong mã nguồn có chữ ký của gói cài. Cấu hình chỉ được
# THU HẸP tập này, không bao giờ mở rộng. Một file cấu hình bị sửa (kể cả đã ký
# bằng khoá bị lộ) vẫn không tạo ra được action mà mã nguồn chưa biết.
KNOWN_ACTIONS = frozenset({
    "alert",              # Level 0: chỉ ghi nhận.
    "snapshot_state",     # Level 1: chụp hiện trạng, không đổi gì.
    "block_ip",           # Level 2: có TTL, gỡ được.
    "rate_limit_ip",      # Level 2: làm chậm thay vì cắt — đoán sai ít hại hơn.
    "isolate_endpoint",   # Level 3: chỉ sau khi đạt release gate netns/VM.
    "stop_process",       # Level 4: phá huỷ, luôn cần người duyệt.
})

# Action mà policy KHÔNG BAO GIỜ được đánh dấu tự động, dù cấu hình nói gì.
# Đây là dòng cuối cùng giữa "một file cấu hình sai" và "máy tự giết tiến trình
# production lúc 3 giờ sáng".
NEVER_AUTOMATIC = frozenset({"stop_process"})

MAX_TTL_CEILING_S = 3600


@dataclass(frozen=True)
class PolicyConfig:
    """Cấu hình phản ứng. Chỉ nạp từ file đã ký."""

    policy_mode: str = "audit_only"          # audit_only | recommend | auto
    min_risk_score: int = 85
    auto_rules: frozenset[str] = frozenset()
    auto_actions: frozenset[str] = frozenset()
    max_ttl_s: int = 300
    max_actions_per_hour: int = 6

    def __post_init__(self) -> None:
        if self.policy_mode not in {"audit_only", "recommend", "auto"}:
            raise ValueError(f"policy_mode không hợp lệ: {self.policy_mode!r}")
        unknown = set(self.auto_actions) - KNOWN_ACTIONS
        if unknown:
            raise ValueError(f"action không nằm trong allowlist mã nguồn: {sorted(unknown)}")
        forbidden = set(self.auto_actions) & NEVER_AUTOMATIC
        if forbidden:
            raise ValueError(f"action không bao giờ được tự động: {sorted(forbidden)}")
        if not 1 <= self.max_ttl_s <= MAX_TTL_CEILING_S:
            raise ValueError(f"max_ttl_s phải trong 1..{MAX_TTL_CEILING_S}")
        if not 0 <= self.min_risk_score <= 100:
            raise ValueError("min_risk_score phải trong 0..100")
        if self.max_actions_per_hour < 0:
            raise ValueError("max_actions_per_hour không được âm")

    @classmethod
    def from_dict(cls, raw: dict) -> "PolicyConfig":
        known = set(cls.__dataclass_fields__)
        unknown = set(raw) - known
        if unknown:
            # Fail closed: một khoá lạ có thể là khoá cũ đã đổi tên, và bỏ qua
            # nó âm thầm nghĩa là chạy với policy KHÁC cái người vận hành viết.
            raise ValueError(f"khoá cấu hình không nhận ra: {sorted(unknown)}")
        return cls(
            policy_mode=str(raw.get("policy_mode", "audit_only")),
            min_risk_score=int(raw.get("min_risk_score", 85)),
            auto_rules=frozenset(str(r) for r in raw.get("auto_rules", ())),
            auto_actions=frozenset(str(a) for a in raw.get("auto_actions", ())),
            max_ttl_s=int(raw.get("max_ttl_s", 300)),
            max_actions_per_hour=int(raw.get("max_actions_per_hour", 6)),
        )

    @classmethod
    def load(cls, path: Path, public_key: Path | None = None,
             signature: Path | None = None) -> "PolicyConfig":
        """Nạp cấu hình. Không có khoá công khai thì chỉ cho phép audit_only.

        Lý do: cấu hình phản ứng tự động là thứ kẻ tấn công muốn sửa nhất trên
        máy đã chiếm được. Cho phép nó bật auto-response từ một file thường là
        tự trao vũ khí.
        """
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("policy config phải là một object JSON")
        config = cls.from_dict(raw)
        if config.policy_mode == "audit_only":
            return config
        if public_key is None or signature is None:
            raise ValueError(
                "policy_mode ngoài audit_only yêu cầu cấu hình đã ký "
                "(thiếu khoá công khai hoặc chữ ký)")
        from shield.security.supply_chain import verify_detached_signature
        ok, message = verify_detached_signature(Path(path), Path(signature), Path(public_key))
        if not ok:
            raise ValueError(f"chữ ký policy config không hợp lệ: {message}")
        return config


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    automatic: bool
    reason: str


@dataclass(frozen=True)
class ResponseProposal:
    """Một đề xuất phản ứng. KHÔNG phải một hành động đã xảy ra.

    Phase 0 dừng lại đúng ở đây: proposal được ghi audit và hiện lên UI, không
    có đường nào từ nó tới privileged helper. Đường đó là Phase 4, sau khi mọi
    adapter đã có `verify()` và `rollback()`.
    """

    proposal_id: str
    rule_id: str
    action: str
    target: str
    reason: str
    ttl_s: int
    requires_human: bool
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    created_ts: float = 0.0
    # Cấu hình CÓ cho phép tự động hay không. Ghi lại để Phase 4 dùng và để
    # người vận hành thấy policy của họ thật sự nói gì — nhưng ở Phase 0 nó
    # không mở được đường thực thi nào: `requires_human` luôn True.
    would_be_automatic: bool = False

    def to_dict(self) -> dict:
        return {
            "proposal_id": self.proposal_id, "rule_id": self.rule_id, "action": self.action,
            "target": self.target, "reason": self.reason, "ttl_s": self.ttl_s,
            "requires_human": self.requires_human, "evidence_refs": list(self.evidence_refs),
            "created_ts": self.created_ts, "would_be_automatic": self.would_be_automatic,
            "state": "PROPOSED",
        }


class PolicyEngine:
    def __init__(self, *, audit_only: bool = True, auto_rules: set[str] | None = None,
                 config: PolicyConfig | None = None, clock=time.time) -> None:
        if config is None:
            config = PolicyConfig(
                policy_mode="audit_only" if audit_only else "auto",
                auto_rules=frozenset(auto_rules or ()),
                # Không suy ra action tự động từ tham số cũ: đường nâng cấp phải
                # là khai báo tường minh trong cấu hình đã ký.
                auto_actions=frozenset(),
            )
        self.config = config
        self.audit_only = config.policy_mode == "audit_only"
        self.auto_rules = config.auto_rules
        self._clock = clock
        self._recent: deque[float] = deque()

    # --- quyết định (giữ nguyên chữ ký cũ để phần còn lại của agent không đổi) ---

    def decide(self, rule_id: str, risk_score: int) -> PolicyDecision:
        if self.config.policy_mode == "audit_only":
            return PolicyDecision("alert", False, "policy:audit-only")
        if risk_score < self.config.min_risk_score:
            return PolicyDecision("alert", False, "risk:below-auto-threshold")
        if rule_id not in self.config.auto_rules:
            return PolicyDecision("alert", False, "rule:not-allowlisted")
        if self.config.policy_mode == "recommend":
            return PolicyDecision("contain", False, "policy:recommend-only")
        if not self._within_rate_limit():
            return PolicyDecision("alert", False, "policy:rate-limited")
        return PolicyDecision("contain", True, "policy:allowlisted-high-risk")

    def _within_rate_limit(self) -> bool:
        """Chặn bão: một rule kêu 500 lần trong 10 phút không được thành 500
        lần chặn IP. Giới hạn đếm trên MỌI action, không theo từng rule — kẻ
        tấn công kích nhiều rule khác nhau vẫn bị chặn."""
        if self.config.max_actions_per_hour <= 0:
            return False
        now = self._clock()
        while self._recent and now - self._recent[0] > 3600:
            self._recent.popleft()
        if len(self._recent) >= self.config.max_actions_per_hour:
            return False
        self._recent.append(now)
        return True

    # --- quyết định tất định (kế hoạch 2.0 mục 3.3) ---

    def decide_action(self, incident_id: str, rule_id: str, risk_score: int,
                      action: str, target: dict, evidence_refs=(),
                      *, detector_precision: float | None = None) -> "DecisionOutcome":
        """Quyết định đầy đủ cho một action cụ thể, kèm lý do khi từ chối.

        Từ chối cũng là một quyết định và cũng được ghi lại. Một hệ thống chỉ
        ghi những lần nó hành động sẽ không trả lời được câu hỏi quan trọng
        nhất sau một sự cố: "vì sao lúc đó nó KHÔNG làm gì?"
        """
        from shield.decision.models import ACTION_SPECS, DecisionOutcome, build_decision

        evaluated = {
            "rule_id": rule_id, "risk_score": risk_score, "action": action,
            "policy_mode": self.config.policy_mode,
            "min_risk_score": self.config.min_risk_score,
            "detector_precision": detector_precision,
        }
        if action not in ACTION_SPECS:
            return DecisionOutcome(None, f"action không nằm trong allowlist: {action!r}", evaluated)
        if not evidence_refs:
            # Mục 3.1: "Mọi claim phải có ít nhất một evidence_ref hợp lệ."
            # Một quyết định không bằng chứng không kiểm chứng lại được.
            return DecisionOutcome(None, "quyết định không có bằng chứng nào", evaluated)

        decision = self.decide(rule_id, risk_score)
        downgrade = ""
        mode = "auto"
        requires_human = False

        if decision.action == "alert":
            mode, requires_human, downgrade = "recommend", True, decision.reason
        elif decision.action == "contain" and not decision.automatic:
            mode, requires_human, downgrade = "recommend", True, decision.reason
        if action not in self.config.auto_actions:
            mode, requires_human = "recommend", True
            downgrade = downgrade or "action chưa được cấp phép tự động trong cấu hình"
        if action in NEVER_AUTOMATIC:
            mode, requires_human = "recommend", True
            downgrade = "action phá huỷ — luôn cần người duyệt"

        # Detector chưa hiệu chuẩn thì KHÔNG được tự động. Không biết một
        # detector đúng bao nhiêu phần trăm mà vẫn cho nó tự hành động là đánh
        # cược bằng hệ thống của người khác.
        if mode == "auto" and detector_precision is None:
            mode, requires_human = "recommend", True
            downgrade = "detector chưa được hiệu chuẩn — chưa biết nó đúng bao nhiêu"

        built = build_decision(
            incident_id, action, target,
            policy_rule_id=rule_id,
            evidence_refs=evidence_refs,
            mode=mode,
            ttl_s=self.config.max_ttl_s,
            requires_human=requires_human,
            reason=decision.reason,
            downgrade_reason=downgrade,
        )
        return DecisionOutcome(built, "", evaluated)

    # --- đề xuất ---

    def propose(self, rule_id: str, risk_score: int, action: str, target: str,
                evidence_refs: tuple[str, ...] = ()) -> ResponseProposal | None:
        """Sinh một đề xuất phản ứng, hoặc None nếu policy không đề xuất gì.

        `action` PHẢI nằm trong allowlist mã nguồn. Chuỗi lạ bị từ chối chứ
        không được truyền tiếp — đây là chỗ duy nhất một action ID từ bên ngoài
        đi vào hệ thống, nên nó phải đóng.
        """
        if action not in KNOWN_ACTIONS:
            return None
        decision = self.decide(rule_id, risk_score)
        if decision.action == "alert":
            return None
        would_be_automatic = (
            decision.automatic
            and action in self.config.auto_actions
            and action not in NEVER_AUTOMATIC
        )
        return ResponseProposal(
            proposal_id=uuid.uuid4().hex,
            rule_id=rule_id,
            action=action,
            target=target,
            reason=decision.reason,
            ttl_s=min(self.config.max_ttl_s, MAX_TTL_CEILING_S),
            # Phase 0: LUÔN cần người duyệt, kể cả khi cấu hình cho phép tự
            # động. Cờ `automatic` được tính đúng và ghi lại để Phase 4 dùng,
            # nhưng chưa có đường thực thi nào đọc nó.
            requires_human=True,
            evidence_refs=tuple(evidence_refs),
            created_ts=self._clock(),
            would_be_automatic=would_be_automatic,
        )
