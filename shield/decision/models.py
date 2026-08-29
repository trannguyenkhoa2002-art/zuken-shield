"""Quyết định phản ứng — tất định, phát lại được (mục 3.3).

Bất biến trung tâm: **cùng đầu vào, cùng cấu hình thì luôn ra cùng quyết định.**
Không đồng hồ, không ngẫu nhiên, không thứ tự dict phụ thuộc lần chạy nào lọt
được vào `decision_id`. Nhờ đó một quyết định gây tranh cãi có thể dựng lại
được từ audit log sáu tháng sau, và câu trả lời sẽ giống hệt.

Vì sao AI chỉ được đề xuất một action ID chứ không được điền cả cấu trúc này:
mọi trường còn lại — TTL, blast radius, tiền điều kiện, kế hoạch rollback — đến
từ allowlist trong mã nguồn và cấu hình đã ký. Nếu model điền được `ttl_s` thì
nó đặt được 86400 giây; nếu nó điền được `rollback_plan` thì nó viết được một
kế hoạch rollback rỗng. Chỉ cho nó chọn một cái tên, và Shield tra ra phần còn
lại, là khác biệt giữa "AI đề xuất" và "AI điều khiển".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

# Mức đặc quyền theo mục 3.3. Con số là bậc thang, không phải điểm.
LEVEL_OBSERVE = 0
LEVEL_RECOMMEND = 1
LEVEL_SAFE_AUTO = 2
LEVEL_CONTAINMENT = 3
LEVEL_DESTRUCTIVE = 4

# Bảng tra CỨNG cho mỗi action: mức, TTL trần, phạm vi ảnh hưởng, tiền điều
# kiện, hậu điều kiện và kế hoạch rollback. Đây là nguồn sự thật duy nhất —
# cấu hình chỉ được THU HẸP nó (bỏ bớt action), không bao giờ mở rộng.
ACTION_SPECS: dict[str, dict] = {
    "alert": {
        "level": LEVEL_OBSERVE, "max_ttl_s": 0, "blast_radius": "none",
        "reversible": True,
        "preconditions": (), "postconditions": (),
        "rollback": {"action": "none", "reason": "ghi nhận không đổi trạng thái hệ thống"},
    },
    "snapshot_state": {
        "level": LEVEL_RECOMMEND, "max_ttl_s": 0, "blast_radius": "local-readonly",
        "reversible": True,
        "preconditions": ("disk_space_available",),
        "postconditions": ("snapshot_file_exists",),
        "rollback": {"action": "delete_snapshot", "reason": "xoá file đã chụp"},
    },
    "block_ip": {
        "level": LEVEL_SAFE_AUTO, "max_ttl_s": 3600, "blast_radius": "single-peer",
        "reversible": True,
        "preconditions": ("target_not_in_protected_allowlist", "target_is_not_gateway",
                          "target_is_not_dns_resolver"),
        "postconditions": ("nft_element_present", "ttl_within_limit"),
        "rollback": {"action": "unblock_ip", "reason": "xoá phần tử khỏi set nftables"},
    },
    "rate_limit_ip": {
        "level": LEVEL_SAFE_AUTO, "max_ttl_s": 3600, "blast_radius": "single-peer",
        "reversible": True,
        "preconditions": ("target_not_in_protected_allowlist", "target_is_not_gateway",
                          "target_is_not_dns_resolver"),
        "postconditions": ("nft_element_present", "ttl_within_limit"),
        "rollback": {"action": "unrate_limit_ip", "reason": "xoá phần tử khỏi set nftables"},
    },
    "isolate_endpoint": {
        "level": LEVEL_CONTAINMENT, "max_ttl_s": 3600, "blast_radius": "whole-host",
        "reversible": True,
        "preconditions": ("dead_man_switch_available", "management_ip_known",
                          "privileged_helper_available"),
        "postconditions": ("isolation_table_verified", "management_path_reachable"),
        "rollback": {"action": "release_isolation", "reason": "xoá table cách ly"},
    },
    "stop_process": {
        "level": LEVEL_DESTRUCTIVE, "max_ttl_s": 0, "blast_radius": "single-process",
        # KHÔNG reversible: một tiến trình đã bị giết không sống lại được. Ghi
        # rõ ở đây vì mục 4.2 cấm thêm action thiếu rollback TRỪ KHI nó được
        # khai báo tường minh là không đảo ngược và luôn cần người.
        "reversible": False,
        "preconditions": ("pid_identity_matches", "process_is_not_critical_service"),
        "postconditions": ("process_no_longer_running",),
        "rollback": {"action": "none", "reason": "không đảo ngược được — luôn cần người duyệt"},
    },
}

# Mức tối đa được phép tự động ở 2.0. Mục 3.2 của kế hoạch: chỉ một tập nhỏ
# Level 2, và Level 3 chỉ sau khi đạt release gate trên VM/netns.
MAX_AUTOMATIC_LEVEL = LEVEL_SAFE_AUTO


@dataclass(frozen=True)
class Decision:
    decision_id: str
    incident_id: str
    action: str
    target: dict
    evidence_refs: tuple[str, ...]
    policy_rule_id: str
    mode: str                      # recommend | auto
    ttl_s: int
    blast_radius: str
    level: int
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    rollback_plan: dict
    requires_human: bool
    reason: str = ""
    # Vì sao bị hạ cấp hoặc từ chối. Mục 3.4 gate: "Policy downgrade/deny được
    # audit rõ lý do." Rỗng nghĩa là không có hạ cấp nào.
    downgrade_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id, "incident_id": self.incident_id,
            "action": self.action, "target": dict(self.target),
            "evidence_refs": list(self.evidence_refs),
            "policy_rule_id": self.policy_rule_id, "mode": self.mode,
            "ttl_s": self.ttl_s, "blast_radius": self.blast_radius, "level": self.level,
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "rollback_plan": dict(self.rollback_plan),
            "requires_human": self.requires_human, "reason": self.reason,
            "downgrade_reason": self.downgrade_reason,
        }


@dataclass(frozen=True)
class DecisionOutcome:
    """Kết quả một lượt quyết định, kể cả khi kết quả là 'không làm gì'.

    Từ chối cũng là một quyết định và cũng phải được ghi lại. Một hệ thống chỉ
    ghi những lần nó hành động sẽ không trả lời được câu hỏi quan trọng nhất
    sau một sự cố: "vì sao lúc đó nó KHÔNG làm gì?"
    """

    decision: Decision | None
    denied_reason: str = ""
    evaluated: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.to_dict() if self.decision else None,
            "denied_reason": self.denied_reason,
            "evaluated": dict(self.evaluated),
        }


def decision_id_for(incident_id: str, action: str, target: dict,
                    policy_rule_id: str, evidence_refs) -> str:
    """ID tất định, suy ra từ nội dung quyết định.

    KHÔNG dùng uuid4: cùng một đầu vào phải ra cùng một ID, nếu không thì
    "phát lại quyết định" không kiểm chứng được gì — mọi lần chạy đều ra một ID
    mới và không có cách nào đối chiếu với bản ghi cũ.

    `sort_keys=True` là bắt buộc: thứ tự khoá trong dict phụ thuộc thứ tự chèn.
    """
    payload = json.dumps({
        "incident_id": incident_id, "action": action, "target": target,
        "policy_rule_id": policy_rule_id, "evidence_refs": sorted(evidence_refs),
    }, sort_keys=True, separators=(",", ":"), default=str)
    return "decision:" + hashlib.sha256(payload.encode()).hexdigest()[:32]


def build_decision(incident_id: str, action: str, target: dict, *,
                   policy_rule_id: str, evidence_refs, mode: str,
                   ttl_s: int, requires_human: bool, reason: str = "",
                   downgrade_reason: str = "") -> Decision:
    """Dựng một quyết định. Mọi trường không phải `action` đến từ ACTION_SPECS.

    Đây là chỗ ép nguyên tắc của mục 3.3: "AI chỉ được đề xuất một action ID và
    evidence; policy engine tự resolve phần còn lại từ allowlist/config."
    """
    spec = ACTION_SPECS.get(action)
    if spec is None:
        raise ValueError(f"action không nằm trong allowlist: {action!r}")
    if mode not in {"recommend", "auto"}:
        raise ValueError(f"mode không hợp lệ: {mode!r}")

    capped_ttl = max(0, min(int(ttl_s), int(spec["max_ttl_s"])))
    if spec["max_ttl_s"] > 0 and capped_ttl <= 0:
        # Một action có TTL mà TTL bằng 0 nghĩa là chặn vĩnh viễn. Mục 4.3 đòi
        # mọi auto action đều có TTL, nên đây phải là lỗi chứ không phải mặc định.
        raise ValueError(f"{action} bắt buộc phải có TTL dương")

    # SẮP XẾP, không chỉ khử trùng. `decision_id` đã sắp nên nó ổn định; nếu
    # danh sách lưu lại vẫn giữ thứ tự đầu vào thì hai quyết định cùng ID lại
    # khác nội dung, và "phát lại" chỉ đúng một nửa — đúng nửa không ai kiểm.
    refs = tuple(sorted(dict.fromkeys(str(ref) for ref in evidence_refs)))
    return Decision(
        decision_id=decision_id_for(incident_id, action, target, policy_rule_id, refs),
        incident_id=str(incident_id),
        action=action,
        target=dict(target),
        evidence_refs=refs,
        policy_rule_id=str(policy_rule_id),
        mode=mode,
        ttl_s=capped_ttl,
        blast_radius=str(spec["blast_radius"]),
        level=int(spec["level"]),
        preconditions=tuple(spec["preconditions"]),
        postconditions=tuple(spec["postconditions"]),
        rollback_plan=dict(spec["rollback"]),
        # Level trên trần tự động, hoặc action không đảo ngược được, thì LUÔN
        # cần người — bất kể cấu hình nói gì.
        requires_human=bool(requires_human
                            or int(spec["level"]) > MAX_AUTOMATIC_LEVEL
                            or not spec["reversible"]),
        reason=reason,
        downgrade_reason=downgrade_reason,
    )
