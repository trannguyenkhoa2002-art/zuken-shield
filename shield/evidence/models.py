"""Kiểu dữ liệu của evidence graph (KE-HOACH-SHIELD-2.0.md mục 1.2 và 1.3).

Ba nguyên tắc, lấy thẳng từ mục 3.1 của kế hoạch:

1. **Mọi cạnh phải trỏ về event gốc.** `Edge` không tạo được nếu không có ít
   nhất một `evidence_ref`. Không có cửa sau nào cho "cạnh này đúng vì tôi nói
   vậy" — kể cả khi người nói là mã tất định của chính Shield.
2. **Phân biệt observed / derived / inferred / external_intel.** Một cạnh suy
   ra từ hai event khác nhau không cùng hạng với một cạnh đọc thẳng từ một
   event, và UI phải nhìn thấy khác biệt đó.
3. **Trust không tự lên.** Cạnh giữ trust của bằng chứng sinh ra nó, KHÔNG bao
   giờ thừa hưởng trust của thực thể hai đầu. Đây là thứ chặn kịch bản: kẻ tấn
   công bắn syslog giả mạo trùng khoá định danh của một máy đã được quan sát
   cục bộ, rồi mọi khẳng định của hắn được nâng lên mức tin cậy của máy đó.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from shield.common.models import trust_rank

# 12 loại thực thể của mục 1.2. Tập ĐÓNG: một loại lạ nghĩa là ai đó đang nhét
# dữ liệu vào chỗ chưa được thiết kế cho nó, và câu truy vấn sau này sẽ bỏ sót
# nó trong im lặng.
ENTITY_TYPES = frozenset({
    "host", "device", "user", "session", "process", "file",
    "ip", "domain", "service", "credential_indicator", "incident", "response_action",
})

# Quan hệ tối thiểu của mục 1.3. Cũng là tập đóng, cùng lý do.
RELATIONS = frozenset({
    "logged_into",    # user   -> host
    "belongs_to",     # session-> user
    "ran_on",         # process-> host
    "spawned",        # process-> process
    "wrote",          # process-> file
    "connected_to",   # process-> ip | domain
    # process -> service. "Tiến trình này đang giữ socket lắng nghe của cổng
    # đó". Nhiều-nhiều: một socket lắng nghe có thể do nhiều tiến trình giữ
    # (fork kế thừa fd, `SO_REUSEPORT`).
    #
    # Không quan hệ nào có sẵn diễn đạt được điều này. `ran_on` là
    # process -> host; mượn nó cho service -> process sẽ làm câu hỏi "tiến
    # trình này chạy trên máy nào" trở nên vô nghĩa — cùng lý do resolver đã
    # từ chối mượn `logged_into` cho `uid`.
    #
    # Chiều process -> service theo đúng văn phạm sẵn có của đồ thị: tiến
    # trình luôn là chủ thể (`ran_on`, `wrote`, `connected_to`).
    "listens_on",
    "has_hash",       # file   -> credential_indicator (chỉ dấu)
    "supported_by",   # alert  -> event
    "contains",       # incident -> alert
    "affected",       # response_action -> entity
})


class EvidenceKind:
    """Bằng chứng đến từ đâu — quyết định nó nặng bao nhiêu."""

    OBSERVED = "observed"            # đọc thẳng từ một event thu được
    DERIVED = "derived"              # suy ra tất định từ nhiều event
    INFERRED = "inferred"            # suy đoán; KHÔNG bao giờ tự xác nhận điều gì
    EXTERNAL_INTEL = "external_intel"  # nguồn ngoài; chỉ để đối chứng

    ALL = frozenset({OBSERVED, DERIVED, INFERRED, EXTERNAL_INTEL})

    # Thứ hạng để so sánh. `inferred` và `external_intel` cố ý CÙNG hạng thấp
    # nhất: cả hai đều không được một mình xác nhận một kết luận (mục 2.4).
    RANK = {OBSERVED: 3, DERIVED: 2, INFERRED: 1, EXTERNAL_INTEL: 1}


def entity_id_for(entity_type: str, canonical_key: str) -> str:
    """ID ổn định, suy ra từ (loại, khoá chuẩn) — KHÔNG ngẫu nhiên.

    Tất định là bắt buộc: hai tiến trình khác nhau quan sát cùng một máy phải
    ra cùng một ID, nếu không graph sẽ đầy thực thể song trùng và mọi câu hỏi
    "máy này còn làm gì nữa" đều trả lời thiếu.
    """
    if entity_type not in ENTITY_TYPES:
        raise ValueError(f"loại thực thể không hợp lệ: {entity_type!r}")
    if not canonical_key:
        raise ValueError("khoá chuẩn không được rỗng")
    digest = hashlib.sha256(f"{entity_type}\x00{canonical_key}".encode()).hexdigest()
    return f"{entity_type}:{digest[:24]}"


@dataclass(frozen=True)
class Entity:
    entity_type: str
    canonical_key: str
    attributes: dict = field(default_factory=dict)
    aliases: tuple[str, ...] = ()
    first_seen: float = 0.0
    last_seen: float = 0.0
    trust: str = "local"
    provenance: str = ""
    criticality: str = "normal"        # low | normal | high | critical
    resolution_confidence: float = 1.0  # độ tin của phép hợp nhất danh tính

    def __post_init__(self) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(f"loại thực thể không hợp lệ: {self.entity_type!r}")
        if not self.canonical_key:
            raise ValueError("khoá chuẩn không được rỗng")
        if not 0.0 <= self.resolution_confidence <= 1.0:
            raise ValueError("resolution_confidence phải trong 0..1")

    @property
    def entity_id(self) -> str:
        return entity_id_for(self.entity_type, self.canonical_key)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id, "entity_type": self.entity_type,
            "canonical_key": self.canonical_key, "attributes": dict(self.attributes),
            "aliases": list(self.aliases), "first_seen": self.first_seen,
            "last_seen": self.last_seen, "trust": self.trust,
            "provenance": self.provenance, "criticality": self.criticality,
            "resolution_confidence": self.resolution_confidence,
        }


@dataclass(frozen=True)
class Edge:
    src_id: str
    relation: str
    dst_id: str
    evidence_refs: tuple[str, ...]
    trust: str
    derived_by: str                      # tên detector/resolver đã tạo cạnh này
    evidence_kind: str = EvidenceKind.OBSERVED
    first_seen: float = 0.0
    last_seen: float = 0.0
    confidence: float = 1.0
    attributes: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.relation not in RELATIONS:
            raise ValueError(f"quan hệ không hợp lệ: {self.relation!r}")
        if not self.src_id or not self.dst_id:
            raise ValueError("cạnh phải có cả hai đầu")
        if self.src_id == self.dst_id and self.relation != "spawned":
            # `spawned` tự trỏ về mình là chuyện có thật (tiến trình fork ra
            # chính nó trong bảng); mọi quan hệ khác thì không.
            raise ValueError("cạnh tự trỏ về mình không hợp lệ")
        if not self.evidence_refs:
            # Đây là bất biến trung tâm của cả Phase 1. Một cạnh không có bằng
            # chứng là một khẳng định không kiểm chứng được, và graph đầy những
            # thứ đó thì không còn là bằng chứng nữa mà là ý kiến.
            raise ValueError("cạnh phải có ít nhất một evidence_ref")
        for ref in self.evidence_refs:
            if ":" not in ref or ref.split(":", 1)[0] not in {"event", "alert", "incident", "intel"}:
                raise ValueError(f"evidence_ref không hợp lệ: {ref!r}")
        if self.evidence_kind not in EvidenceKind.ALL:
            raise ValueError(f"loại bằng chứng không hợp lệ: {self.evidence_kind!r}")
        if not self.derived_by:
            raise ValueError("cạnh phải ghi ai đã tạo ra nó")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence phải trong 0..1")

    @property
    def edge_id(self) -> str:
        digest = hashlib.sha256(
            f"{self.src_id}\x00{self.relation}\x00{self.dst_id}".encode()
        ).hexdigest()
        return f"edge:{digest[:32]}"

    def to_dict(self) -> dict:
        return {
            "edge_id": self.edge_id, "src_id": self.src_id, "relation": self.relation,
            "dst_id": self.dst_id, "evidence_refs": list(self.evidence_refs),
            "evidence_kind": self.evidence_kind, "trust": self.trust,
            "derived_by": self.derived_by, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "confidence": self.confidence,
            "attributes": dict(self.attributes),
        }


def merge_trust(existing: str, incoming: str) -> str:
    """Trust của một cạnh khi có thêm bằng chứng mới.

    Lấy mức CAO HƠN — nhưng chỉ vì hai bên đều là bằng chứng CỦA CHÍNH cạnh đó.
    Bằng chứng mới, độc lập, đáng tin hơn thì cạnh đáng tin hơn; điều đó đúng.

    Cái KHÔNG được phép là để cạnh thừa hưởng trust từ thực thể ở hai đầu. Một
    dòng syslog giả mạo nhắc tới một máy đã được quan sát cục bộ vẫn chỉ là một
    dòng syslog giả mạo. `Graph` không bao giờ gọi hàm này với trust của thực
    thể — xem `graph.py`.
    """
    return existing if trust_rank(existing) >= trust_rank(incoming) else incoming


def canonical_json(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def now() -> float:
    return time.time()
