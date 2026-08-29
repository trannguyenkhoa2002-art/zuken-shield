"""Bộ phân tích cục bộ, tất định — phương án dự phòng bắt buộc (gate Phase 2).

Đây KHÔNG phải một model. Nó không đoán, không sinh văn bản, không có tham số
ngẫu nhiên: cùng một đầu vào luôn cho cùng một đầu ra, và mọi câu nó viết ra
đều ghép từ dữ kiện đã có trong `InvestigationRequest`.

Vì sao nó tồn tại: gate Phase 2 đòi "có deterministic local analyzer làm
fallback". Nhưng lý do thật sâu hơn — nó là thước đo. Nếu một model ngôn ngữ
không nói được gì hữu ích hơn file này, thì việc bật model đó chỉ thêm rủi ro
mà không thêm giá trị, và cần có một mốc để so.

Nó cũng cố ý khiêm tốn: mọi giả thuyết nó sinh ra đều mang trạng thái
`unconfirmed`. Một bộ đếm không xác nhận được điều gì.
"""

from __future__ import annotations

import collections
import time

from shield.ai.contracts import Hypothesis, InvestigationRequest, InvestigationResult

# Mẫu hành vi đáng chú ý. Cố ý ÍT và tường minh: mỗi mục ở đây là một câu
# khẳng định về thế giới, và một danh sách dài không ai đọc lại sẽ đầy những
# khẳng định không còn đúng.
# Mã NGẮN, và đó không phải chuyện thẩm mỹ: `Hypothesis.id` bị hợp đồng giới
# hạn 32 ký tự, và id được ghép thành `H-{mã}-{n}`. Mã dài hơn 29 ký tự làm
# MỌI giả thuyết của mẫu đó ném `SchemaViolation` — tức là mẫu ấy im lặng biến
# mất, không phải hỏng ồn ào. `process_spawned_many_children` đã dài đúng một
# ký tự như thế và chưa lần nào chạy được.
_WRITE_THEN_CONNECT = "write_then_connect"
_MANY_CHILDREN = "many_children"
_NEW_LISTENER = "new_listener"


class LocalDeterministicAnalyst:
    name = "local"
    model = "deterministic-v1"

    def __init__(self, *, min_children: int = 8) -> None:
        self.min_children = min_children

    async def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        hypotheses: list[Hypothesis] = []
        by_relation: dict[str, list[dict]] = collections.defaultdict(list)
        for fact in request.facts:
            by_relation[str(fact.get("relation", ""))].append(fact)

        hypotheses.extend(self._write_then_connect(by_relation))
        hypotheses.extend(self._many_children(by_relation))
        hypotheses.extend(self._new_listeners(by_relation))

        counts = {relation: len(items) for relation, items in sorted(by_relation.items()) if relation}
        breakdown = ", ".join(f"{relation}={count}" for relation, count in counts.items())
        query_keys = self._query_keys(hypotheses)
        return InvestigationResult(
            investigation_id=request.investigation_id,
            incident_id=request.incident_id,
            # Câu tiếng Việt vẫn được giữ làm phương án cuối cho nơi không có
            # bảng dịch (nhật ký, xuất báo cáo). Giao diện dùng KHOÁ.
            summary=f"Phân tích cục bộ tất định. {breakdown or 'không có quan hệ nào.'}"[:2000],
            summary_key="ai.local.summary" if breakdown else "ai.local.summary_empty",
            summary_params={"breakdown": breakdown},
            hypotheses=tuple(hypotheses),
            recommended_queries=tuple(self._queries(hypotheses)),
            query_keys=tuple(query_keys),
            recommended_actions=("snapshot_state",) if hypotheses else (),
            limitations=(
                "Bộ phân tích cục bộ chỉ đếm và ghép quan hệ; nó không suy luận "
                "về ý đồ và không xác nhận được điều gì.",
            ),
            limitation_keys=("ai.local.limitation",),
            provider=self.name, model=self.model, analysed_ts=time.time(),
        )

    # --- mẫu ---

    def _write_then_connect(self, by_relation) -> list[Hypothesis]:
        wrote = {str(f.get("src_id")): f for f in by_relation.get("wrote", [])}
        connected = {str(f.get("src_id")): f for f in by_relation.get("connected_to", [])}
        out = []
        for index, src in enumerate(sorted(set(wrote) & set(connected))):
            if index >= 5:
                break
            refs = tuple(dict.fromkeys(
                list(wrote[src].get("evidence_refs", []))
                + list(connected[src].get("evidence_refs", []))
            ))[:32]
            if not refs:
                continue
            out.append(Hypothesis(
                id=f"H-{_WRITE_THEN_CONNECT}-{index + 1}",
                statement=(f"Tiến trình {src} ghi một file rồi mở kết nối ra ngoài "
                           "trong cùng cửa sổ điều tra."),
                statement_key="ai.local.h_write_connect",
                statement_params={"process": src},
                status="unconfirmed",
                evidence_refs=refs,
                missing_evidence=("Chưa biết file đã ghi có được thực thi lại hay không.",),
                missing_evidence_keys=("ai.local.missing_exec",),
                confidence_label="medium" if len(refs) >= 2 else "low",
            ))
        return out

    def _many_children(self, by_relation) -> list[Hypothesis]:
        children = collections.Counter(
            str(f.get("src_id")) for f in by_relation.get("spawned", []))
        out = []
        for index, (parent, count) in enumerate(children.most_common(3)):
            if count < self.min_children:
                break
            refs = tuple(dict.fromkeys(
                ref for fact in by_relation["spawned"]
                if str(fact.get("src_id")) == parent
                for ref in fact.get("evidence_refs", [])
            ))[:32]
            if not refs:
                continue
            out.append(Hypothesis(
                id=f"H-{_MANY_CHILDREN}-{index + 1}",
                statement=f"Tiến trình {parent} sinh ra {count} tiến trình con.",
                statement_key="ai.local.h_many_children",
                statement_params={"process": parent, "count": count},
                status="unconfirmed",
                evidence_refs=refs,
                missing_evidence=("Chưa so với hành vi thường ngày của tiến trình này.",),
                missing_evidence_keys=("ai.local.missing_baseline",),
                confidence_label="low",
            ))
        return out

    def _new_listeners(self, by_relation) -> list[Hypothesis]:
        services = [f for f in by_relation.get("ran_on", [])
                    if str(f.get("src_type")) == "service"]
        out = []
        for index, fact in enumerate(services[:3]):
            refs = tuple(fact.get("evidence_refs", []))[:32]
            if not refs:
                continue
            out.append(Hypothesis(
                id=f"H-{_NEW_LISTENER}-{index + 1}",
                statement=f"Dịch vụ {fact.get('src_id')} mở cổng lắng nghe.",
                statement_key="ai.local.h_new_listener",
                statement_params={"service": str(fact.get("src_id"))},
                status="unconfirmed",
                evidence_refs=refs,
                missing_evidence=("Chưa biết cổng này đã mở từ trước hay mới xuất hiện.",),
                missing_evidence_keys=("ai.local.missing_port_history",),
                confidence_label="low",
            ))
        return out

    @staticmethod
    def _queries(hypotheses) -> list[str]:
        queries = []
        for hypothesis in hypotheses:
            if _WRITE_THEN_CONNECT in hypothesis.id:
                queries.append("get_file_history cho file đã ghi")
                queries.append("get_process_ancestry cho tiến trình liên quan")
            elif _MANY_CHILDREN in hypothesis.id:
                queries.append("compare_with_baseline cho số tiến trình con")
        return list(dict.fromkeys(queries))[:20]

    @staticmethod
    def _query_keys(hypotheses) -> list[str]:
        keys = []
        for hypothesis in hypotheses:
            if _WRITE_THEN_CONNECT in hypothesis.id:
                keys.append("ai.local.q_file_history")
                keys.append("ai.local.q_ancestry")
            elif _MANY_CHILDREN in hypothesis.id:
                keys.append("ai.local.q_baseline")
        return list(dict.fromkeys(keys))[:20]
