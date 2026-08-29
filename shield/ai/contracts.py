"""Hợp đồng dữ liệu giữa Shield và một model (mục 2.2).

Output của model KHÔNG được là văn xuôi tự do. Lý do không phải thẩm mỹ: một
đoạn văn không kiểm chứng được từng phần. Với schema, mỗi khẳng định là một
`Hypothesis` có `evidence_refs` riêng, nên validator tất định kiểm được từng
cái một và hạ cấp đúng cái sai thay vì vứt cả bài.

Ba quy tắc của file này:

1. **Strict.** Trường lạ bị TỪ CHỐI, không bị bỏ qua. Bỏ qua âm thầm nghĩa là
   một model (hoặc một kẻ tấn công đã chiếm được model) gửi thêm
   `"policy_action": "isolate"` và không ai thấy.
2. **Model không được đặt số.** Không có trường xác suất. `confidence_label`
   chỉ nhận `low|medium|high`. Mục 3.4: confidence heuristic không được hiển
   thị như xác suất trước khi calibration.
3. **Không có trường nào của model chạm tới hành động.** Không `policy_action`,
   không `command`, không `path`. `recommended_actions` chỉ nhận ID nằm sẵn
   trong allowlist mã nguồn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Trạng thái một giả thuyết được phép mang. Không có "confirmed": một model
# không được xác nhận điều gì. Xác nhận là việc của con người sau khi đọc bằng
# chứng, hoặc của một quy tắc tất định.
HYPOTHESIS_STATUS = frozenset({
    "unconfirmed", "supported", "contradicted", "insufficient_evidence",
})
CONFIDENCE_LABELS = frozenset({"low", "medium", "high"})

# Action model được phép ĐỀ XUẤT. Trùng với allowlist của policy engine, và có
# test khẳng định điều đó — một ID viết lệch ở đây là một đề xuất không bao giờ
# khớp, tức là im lặng không làm gì.
RECOMMENDABLE_ACTIONS = frozenset({
    "alert", "snapshot_state", "block_ip", "rate_limit_ip", "isolate_endpoint",
    "stop_process",
})

MAX_SUMMARY_CHARS = 2000
MAX_TEXT_CHARS = 500
MAX_HYPOTHESES = 12
MAX_REFS_PER_HYPOTHESIS = 32
MAX_LIST_ITEMS = 20

_EVIDENCE_REF = re.compile(r"^(event|alert|incident|intel):[A-Za-z0-9._:@-]{1,128}$")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class SchemaViolation(ValueError):
    """Output của model không khớp hợp đồng. Fail closed."""


def _text(value, *, limit: int = MAX_TEXT_CHARS, field_name: str = "") -> str:
    if not isinstance(value, str):
        raise SchemaViolation(f"{field_name}: phải là chuỗi")
    cleaned = value.replace("\x00", "").strip()
    if len(cleaned) > limit:
        raise SchemaViolation(f"{field_name}: dài quá {limit} ký tự")
    return cleaned


def _ref_list(values, *, field_name: str, limit: int = MAX_REFS_PER_HYPOTHESIS) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        raise SchemaViolation(f"{field_name}: phải là danh sách")
    if len(values) > limit:
        raise SchemaViolation(f"{field_name}: quá {limit} phần tử")
    refs = []
    for item in values:
        if not isinstance(item, str) or not _EVIDENCE_REF.match(item):
            # Một ref sai định dạng KHÔNG được bỏ qua: nó là dấu hiệu model
            # đang bịa, và bịa một ref là cách rẻ nhất để làm một khẳng định
            # trông có căn cứ.
            raise SchemaViolation(f"{field_name}: evidence_ref không hợp lệ: {item!r}")
        refs.append(item)
    return tuple(dict.fromkeys(refs))


@dataclass(frozen=True)
class Hypothesis:
    id: str
    statement: str
    status: str = "unconfirmed"
    evidence_refs: tuple[str, ...] = ()
    contradicting_evidence_refs: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    confidence_label: str = "low"
    # Validator ghi lại vì sao nó hạ cấp. Người đọc phải thấy được rằng máy đã
    # can thiệp, không chỉ thấy kết quả sau can thiệp.
    downgrade_reason: str = ""
    # --- chỉ dùng NỘI BỘ, không bao giờ đọc từ output của model ---
    #
    # Một producer tất định của Shield (local_provider) sinh ra khoá dịch thay
    # vì câu, để giao diện tiếng Anh không hiện câu tiếng Việt. Model KHÔNG
    # được đặt hai trường này: cho model chọn khoá i18n nghĩa là cho nó chọn
    # bất kỳ chuỗi nào trong giao diện, kể cả chuỗi cảnh báo bảo mật.
    statement_key: str = ""
    statement_params: dict = field(default_factory=dict)
    missing_evidence_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _ID.match(self.id or ""):
            raise SchemaViolation(f"hypothesis id không hợp lệ: {self.id!r}")
        if self.status not in HYPOTHESIS_STATUS:
            raise SchemaViolation(f"status không hợp lệ: {self.status!r}")
        if self.confidence_label not in CONFIDENCE_LABELS:
            raise SchemaViolation(f"confidence_label không hợp lệ: {self.confidence_label!r}")
        if not self.statement:
            raise SchemaViolation("hypothesis phải có statement")

    @classmethod
    def parse(cls, raw) -> "Hypothesis":
        if not isinstance(raw, dict):
            raise SchemaViolation("hypothesis phải là object")
        # `statement_key` KHÔNG có ở đây, có chủ ý: model không được chọn
        # khoá i18n. Trường lạ bị từ chối nên một model thử đặt nó sẽ bị chặn
        # ngay chứ không bị bỏ qua âm thầm.
        allowed = {"id", "statement", "status", "evidence_refs",
                   "contradicting_evidence_refs", "missing_evidence", "confidence_label"}
        unknown = set(raw) - allowed
        if unknown:
            raise SchemaViolation(f"hypothesis có trường lạ: {sorted(unknown)}")
        missing = raw.get("missing_evidence") or []
        if not isinstance(missing, (list, tuple)) or len(missing) > MAX_LIST_ITEMS:
            raise SchemaViolation("missing_evidence không hợp lệ")
        return cls(
            id=_text(raw.get("id", ""), limit=32, field_name="id"),
            statement=_text(raw.get("statement", ""), field_name="statement"),
            status=str(raw.get("status", "unconfirmed")),
            evidence_refs=_ref_list(raw.get("evidence_refs"), field_name="evidence_refs"),
            contradicting_evidence_refs=_ref_list(
                raw.get("contradicting_evidence_refs"),
                field_name="contradicting_evidence_refs"),
            missing_evidence=tuple(
                _text(item, field_name="missing_evidence") for item in missing),
            confidence_label=str(raw.get("confidence_label", "low")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "statement": self.statement, "status": self.status,
            "evidence_refs": list(self.evidence_refs),
            "contradicting_evidence_refs": list(self.contradicting_evidence_refs),
            "missing_evidence": list(self.missing_evidence),
            "confidence_label": self.confidence_label,
            "downgrade_reason": self.downgrade_reason,
            "statement_key": self.statement_key,
            "statement_params": dict(self.statement_params),
            "missing_evidence_keys": list(self.missing_evidence_keys),
        }


MAX_TOOL_REQUESTS = 4


@dataclass(frozen=True)
class ToolRequest:
    """Model XIN đọc thêm. Nó không gọi được gì — Coordinator gọi.

    Chỉ có tên tool và đối số. KHÔNG có Python, SQL, shell, đường dẫn tự do,
    hay bất cứ thứ gì cần diễn giải: tên phải nằm trong `READ_ONLY_TOOLS`, và
    đối số bị Coordinator ràng buộc lại theo phạm vi của lượt điều tra.
    """

    tool: str
    arguments: dict = field(default_factory=dict)
    # Mã ý định, không phải câu. Model nói vì sao nó xin, bằng một mã đóng —
    # để nhật ký đọc được mà không cần tin văn bản do model sinh.
    intent: str = ""

    @classmethod
    def parse(cls, raw) -> "ToolRequest":
        if not isinstance(raw, dict):
            raise SchemaViolation("tool_request phải là object")
        unknown = set(raw) - {"tool", "arguments", "intent"}
        if unknown:
            raise SchemaViolation(f"tool_request có trường lạ: {sorted(unknown)}")
        arguments = raw.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise SchemaViolation("tool_request.arguments phải là object")
        if len(arguments) > 16:
            raise SchemaViolation("tool_request.arguments quá nhiều trường")
        for key, value in arguments.items():
            if not isinstance(key, str) or not key.isidentifier():
                raise SchemaViolation(f"tên đối số không hợp lệ: {key!r}")
            if not isinstance(value, (str, int, float, bool)) and value is not None:
                # Không nhận cấu trúc lồng: một dict lồng là chỗ để giấu thứ
                # phải được kiểm, và không tool read-only nào cần tới nó.
                raise SchemaViolation(f"đối số {key!r} phải là giá trị đơn")
        return cls(
            tool=_text(raw.get("tool", ""), limit=64, field_name="tool"),
            arguments={k: v for k, v in arguments.items()},
            intent=_text(raw.get("intent", ""), limit=64, field_name="intent"),
        )

    def to_dict(self) -> dict:
        return {"tool": self.tool, "arguments": dict(self.arguments), "intent": self.intent}


@dataclass(frozen=True)
class InvestigationRequest:
    """Thứ Shield đưa cho model. KHÔNG chứa văn bản thô chưa bọc.

    Mục 5.1: "Tách system instruction khỏi event content ở data structure,
    không chỉ prompt text." Cấu trúc này là chỗ tách đó — nội dung telemetry đi
    vào `facts` dưới dạng trường có kiểu, không bao giờ được nối thành câu lệnh.
    """

    investigation_id: str
    incident_id: str
    window_s: float = 3600.0
    facts: tuple[dict, ...] = ()
    entities: tuple[dict, ...] = ()
    allowed_evidence_refs: frozenset[str] = frozenset()

    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id, "incident_id": self.incident_id,
            "window_s": self.window_s, "facts": [dict(f) for f in self.facts],
            "entities": [dict(e) for e in self.entities],
            "allowed_evidence_refs": sorted(self.allowed_evidence_refs),
        }


@dataclass(frozen=True)
class InvestigationResult:
    investigation_id: str
    incident_id: str
    summary: str = ""
    hypotheses: tuple[Hypothesis, ...] = ()
    recommended_queries: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    # Model XIN đọc thêm. Rỗng nghĩa là nó đã xong.
    tool_requests: tuple[ToolRequest, ...] = ()
    provider: str = ""
    model: str = ""
    analysed_ts: float = 0.0
    errors: tuple[str, ...] = field(default_factory=tuple)
    # Nội bộ, như trên: producer tất định nói bằng khoá, model nói bằng câu.
    summary_key: str = ""
    summary_params: dict = field(default_factory=dict)
    limitation_keys: tuple[str, ...] = ()
    query_keys: tuple[str, ...] = ()

    @classmethod
    def parse(cls, raw, *, provider: str = "", model: str = "") -> "InvestigationResult":
        """Đọc output model. Ném SchemaViolation với BẤT KỲ sai lệch nào.

        Fail closed là bắt buộc ở đây: một output nửa hợp lệ được nhận một nửa
        nghĩa là phần bị bỏ qua chính là phần bất thường nhất.
        """
        if not isinstance(raw, dict):
            raise SchemaViolation("kết quả phải là một object JSON")
        allowed = {"investigation_id", "incident_id", "summary", "hypotheses",
                   "recommended_queries", "recommended_actions", "limitations",
                   "tool_requests"}
        unknown = set(raw) - allowed
        if unknown:
            raise SchemaViolation(f"kết quả có trường lạ: {sorted(unknown)}")

        hypotheses_raw = raw.get("hypotheses") or []
        if not isinstance(hypotheses_raw, (list, tuple)):
            raise SchemaViolation("hypotheses phải là danh sách")
        if len(hypotheses_raw) > MAX_HYPOTHESES:
            raise SchemaViolation(f"quá {MAX_HYPOTHESES} giả thuyết")
        hypotheses = tuple(Hypothesis.parse(item) for item in hypotheses_raw)
        seen = [h.id for h in hypotheses]
        if len(set(seen)) != len(seen):
            raise SchemaViolation("hypothesis id trùng nhau")

        actions = raw.get("recommended_actions") or []
        if not isinstance(actions, (list, tuple)) or len(actions) > MAX_LIST_ITEMS:
            raise SchemaViolation("recommended_actions không hợp lệ")
        for action in actions:
            if action not in RECOMMENDABLE_ACTIONS:
                # Model chỉ được chọn từ allowlist. Đây là chỗ DUY NHẤT một
                # chuỗi do model sinh có thể trở thành một action ID, nên nó
                # phải đóng hoàn toàn.
                raise SchemaViolation(f"action không nằm trong allowlist: {action!r}")

        tool_raw = raw.get("tool_requests") or []
        if not isinstance(tool_raw, (list, tuple)):
            raise SchemaViolation("tool_requests phải là danh sách")
        if len(tool_raw) > MAX_TOOL_REQUESTS:
            # Không cho một lượt xin cả trăm tool: quota khó kiểm, thứ tự khó
            # audit, và tài nguyên bật lên theo cụm.
            raise SchemaViolation(f"quá {MAX_TOOL_REQUESTS} tool_requests trong một lượt")
        tool_requests = tuple(ToolRequest.parse(item) for item in tool_raw)

        queries = raw.get("recommended_queries") or []
        limitations = raw.get("limitations") or []
        for name, value in (("recommended_queries", queries), ("limitations", limitations)):
            if not isinstance(value, (list, tuple)) or len(value) > MAX_LIST_ITEMS:
                raise SchemaViolation(f"{name} không hợp lệ")

        return cls(
            investigation_id=_text(raw.get("investigation_id", ""), limit=64,
                                   field_name="investigation_id"),
            incident_id=_text(raw.get("incident_id", ""), limit=64, field_name="incident_id"),
            summary=_text(raw.get("summary", ""), limit=MAX_SUMMARY_CHARS, field_name="summary"),
            hypotheses=hypotheses,
            recommended_queries=tuple(_text(q, field_name="recommended_queries") for q in queries),
            recommended_actions=tuple(str(a) for a in actions),
            limitations=tuple(_text(item, field_name="limitations") for item in limitations),
            tool_requests=tool_requests,
            provider=provider,
            model=model,
        )

    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id, "incident_id": self.incident_id,
            "summary": self.summary,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "recommended_queries": list(self.recommended_queries),
            "recommended_actions": list(self.recommended_actions),
            "limitations": list(self.limitations),
            "tool_requests": [t.to_dict() for t in self.tool_requests],
            "provider": self.provider, "model": self.model,
            "analysed_ts": self.analysed_ts, "errors": list(self.errors),
            "summary_key": self.summary_key, "summary_params": dict(self.summary_params),
            "limitation_keys": list(self.limitation_keys),
            "query_keys": list(self.query_keys),
        }
