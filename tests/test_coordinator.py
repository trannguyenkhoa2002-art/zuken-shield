"""Phase 3B: model XIN đọc thêm, Coordinator GỌI.

Cho model đọc thêm là thứ làm nó hữu ích, và cũng là thứ nguy hiểm nhất có thể
thêm vào lớp AI. Nên mọi bài ở đây hỏi cùng một câu: model làm gì cũng được,
Shield vẫn giữ vô lăng chứ?

`call_tool` đã là điểm thực thi chính sách duy nhất từ Phase 2 và không đổi một
dòng. Coordinator chỉ thêm vòng lặp, thứ tự tất định, và ràng buộc phạm vi.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from shield.ai.contracts import (
    Hypothesis,
    InvestigationRequest,
    InvestigationResult,
    SchemaViolation,
    ToolRequest,
)
from shield.ai.coordinator import MAX_ROUNDS, Coordinator, ScopeViolation
from shield.ai.orchestrator import READ_ONLY_TOOLS, InvestigationOrchestrator


class _Queries:
    def __init__(self) -> None:
        self.calls = []

    def get_evidence(self, ref=None, **kw):
        return {"evidence_kind": "endpoint_telemetry", "trust": "authenticated"}

    def counts(self, **kw):
        self.calls.append(("counts", kw))
        return [{"kind": "socket_connect", "n": 12}]

    def get_entity(self, **kw):
        self.calls.append(("get_entity", kw))
        return {"id": "process:host:1:2"}

    def find_entity(self, **kw):
        self.calls.append(("find_entity", kw))
        return []


def _request(**kw):
    base = dict(investigation_id="inv:1", incident_id="inc:1", window_s=3600.0,
                allowed_evidence_refs=frozenset({"ev:aaa"}))
    base.update(kw)
    return InvestigationRequest(**base)


def _final(summary="xong"):
    return InvestigationResult(investigation_id="inv:1", incident_id="inc:1",
                              summary=summary, provider="fake", model="fixture")


class _Model:
    """Model giả có kịch bản: mỗi lượt trả một kết quả đã định trước."""

    name = "fake"

    def __init__(self, *ket_qua) -> None:
        self.ket_qua = list(ket_qua)
        self.requests = []
        self.lan = 0

    async def investigate(self, request):
        self.requests.append(request)
        item = self.ket_qua[min(self.lan, len(self.ket_qua) - 1)]
        self.lan += 1
        if isinstance(item, Exception):
            raise item
        return item


def _chay(model, request=None, **kw):
    queries = _Queries()
    orch = InvestigationOrchestrator(queries, model)
    token = orch.broker.issue("inc:1", READ_ONLY_TOOLS, tool_budget=orch.max_tool_calls)
    orch._token, orch._incident_id = token.token, "inc:1"
    coordinator = Coordinator(orch, **kw)
    result, trace = asyncio.run(coordinator.run(request or _request()))
    return result, trace, orch, queries


# --- đường thẳng ---


def test_a_model_that_asks_for_nothing_finishes_in_one_round():
    _, trace, orch, _ = _chay(_Model(_final()))
    assert (trace.rounds, trace.termination_reason) == (1, "completed")
    assert orch.tool_calls == []


def test_a_tool_request_is_executed_and_fed_back_as_a_fact():
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts", arguments={"kind": "socket_connect"}),))
    model = _Model(xin, _final())
    result, trace, orch, queries = _chay(model)

    assert trace.termination_reason == "completed"
    assert trace.executed == 1
    assert queries.calls == [("counts", {"kind": "socket_connect"})]
    # Quan sát quay lại model qua CHÍNH `facts`, không qua kênh mới.
    lan_hai = model.requests[1]
    quan_sat = [f for f in lan_hai.facts if f.get("kind") == "tool_observation"]
    assert len(quan_sat) == 1
    assert quan_sat[0]["tool"] == "counts" and quan_sat[0]["row_count"] == 1


# --- 7.1–7.4 model xin sai ---


def test_an_unknown_tool_is_never_executed():
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="rm_rf_slash"),))
    _, trace, orch, queries = _chay(_Model(xin, _final()))

    assert trace.unauthorized_tool_calls == 1
    assert trace.executed == 0
    assert queries.calls == []
    assert orch.policy_violations >= 1


@pytest.mark.parametrize("ten", ["isolate_host", "kill_process", "block_ip",
                                 "execute", "write_file"])
def test_an_action_tool_is_never_executed(ten):
    """3B chỉ đọc. Không tool nào ghi, và tên tool phải nằm trong
    `READ_ONLY_TOOLS` — một registry duy nhất."""
    assert ten not in READ_ONLY_TOOLS
    xin = InvestigationResult(investigation_id="inv:1", incident_id="inc:1",
                             tool_requests=(ToolRequest(tool=ten),))
    _, trace, _, queries = _chay(_Model(xin, _final()))
    assert trace.unauthorized_tool_calls == 1 and queries.calls == []


@pytest.mark.parametrize("doi_so,vi_pham", [
    ({"incident_id": "inc:KHAC"}, "mượn incident khác"),
    ({"window_s": 999999}, "mở rộng cửa sổ thời gian"),
    ({"evidence_ref": "ev:khong_duoc_cap"}, "ref ngoài tập được cấp"),
    ({"since": "khong-phai-so"}, "mốc thời gian không đọc được"),
])
def test_a_request_cannot_widen_its_own_scope(doi_so, vi_pham):
    """TỪ CHỐI, không cắt gọt: cắt một cửa sổ rồi vẫn trả kết quả nghĩa là
    model nhận câu trả lời cho một câu hỏi KHÁC mà nó không được biết."""
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts", arguments=doi_so),))
    _, trace, _, queries = _chay(_Model(xin, _final()))

    assert trace.scope_violations == 1, vi_pham
    assert queries.calls == [], "không được thực thi"
    assert trace.executed == 0


def test_a_window_inside_the_granted_one_is_allowed():
    """Không được từ chối nhầm: thu hẹp phạm vi là hợp lệ."""
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts", arguments={"window_s": 60}),))
    _, trace, _, queries = _chay(_Model(xin, _final()))
    assert trace.scope_violations == 0 and trace.executed == 1


def test_malformed_arguments_fail_closed_at_parse_time():
    """Cấu trúc lồng là chỗ để giấu thứ phải được kiểm."""
    for xau in ({"a": {"lồng": 1}}, {"a": [1, 2]}, {"1abc": 1}):
        with pytest.raises(SchemaViolation):
            ToolRequest.parse({"tool": "counts", "arguments": xau})


# --- 7.5–7.7 trần ---


def test_the_tool_call_budget_stops_the_loop():
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=tuple(ToolRequest(tool="counts", arguments={"i": i})
                            for i in range(4)))
    # Model xin mãi, không bao giờ trả kết luận.
    _, trace, orch, _ = _chay(_Model(xin))
    assert trace.termination_reason in {"max_tool_calls", "max_rounds"}
    assert len(orch.tool_calls) <= orch.max_tool_calls


def test_a_model_that_never_finishes_is_stopped_by_max_rounds():
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts", arguments={"a": 1}),))
    _, trace, _, _ = _chay(_Model(xin))
    assert trace.termination_reason == "max_rounds"
    assert trace.rounds == MAX_ROUNDS


def test_max_rounds_is_not_larger_than_the_tool_budget_allows():
    """Một trần vòng lặp lớn hơn ngân sách tool chỉ tạo ra vòng không làm gì."""
    from shield.ai.contracts import MAX_TOOL_REQUESTS
    from shield.ai.orchestrator import MAX_TOOL_CALLS

    assert MAX_ROUNDS * MAX_TOOL_REQUESTS <= MAX_TOOL_CALLS


def test_repeating_the_same_tool_forever_still_terminates():
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts", arguments={"same": 1}),))
    _, trace, _, queries = _chay(_Model(xin))
    assert trace.rounds == MAX_ROUNDS
    assert len(queries.calls) == MAX_ROUNDS


# --- 7.8–7.10 tool và provider lỗi ---


def test_a_tool_that_raises_does_not_stop_the_investigation():
    class No(_Queries):
        def counts(self, **kw):
            raise RuntimeError("database nổ")

    orch = InvestigationOrchestrator(No(), _Model(
        InvestigationResult(investigation_id="inv:1", incident_id="inc:1",
                            tool_requests=(ToolRequest(tool="counts"),)),
        _final()))
    token = orch.broker.issue("inc:1", READ_ONLY_TOOLS)
    orch._token, orch._incident_id = token.token, "inc:1"
    result, trace = asyncio.run(Coordinator(orch).run(_request()))
    assert trace.termination_reason == "completed"
    assert trace.steps[0]["outcome"] == "tool_error"
    assert result is not None


def test_a_provider_that_explodes_mid_loop_is_recorded_by_type_only():
    """Thông điệp ngoại lệ do mã model sinh và có thể chứa bí mật nó vừa đọc —
    chỉ TÊN KIỂU được ghi."""
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts"),))
    _, trace, _, _ = _chay(_Model(xin, RuntimeError("khoá là AKIAIOSFODNN7EXAMPLE")))
    assert trace.termination_reason == "provider_error"
    assert trace.provider_error_type == "RuntimeError"
    assert "AKIA" not in json.dumps(trace.to_dict())


def test_a_schema_violation_mid_loop_terminates_as_malformed():
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts"),))
    _, trace, _, _ = _chay(_Model(xin, SchemaViolation("rác")))
    assert trace.termination_reason == "malformed_model_output"


# --- 7.11 kill switch ---


def test_the_kill_switch_stops_the_loop_between_rounds(monkeypatch):
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts"),))

    class Bat(_Model):
        async def investigate(self, request):
            result = await super().investigate(request)
            monkeypatch.setenv("SHIELD_AI_KILL_SWITCH", "1")
            return result

    _, trace, _, queries = _chay(Bat(xin))
    assert trace.termination_reason == "kill_switch"
    assert len(queries.calls) <= 1


# --- 7.12 quan sát không sinh ra quyền mới ---


def test_an_observation_cannot_be_used_to_invent_a_new_reference():
    """Quan sát là dữ liệu, không phải giấy phép: một ref xuất hiện trong quan
    sát vẫn không nằm trong `allowed_evidence_refs`."""
    xin = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts", arguments={"evidence_ref": "ev:aaa"}),))
    request = _request()
    _, trace, _, _ = _chay(_Model(xin, _final()), request)
    assert trace.executed == 1
    # ...nhưng một ref khác thì bị chặn, dù nó có thật trong kho.
    xin2 = InvestigationResult(
        investigation_id="inv:1", incident_id="inc:1",
        tool_requests=(ToolRequest(tool="counts", arguments={"evidence_ref": "ev:bbb"}),))
    _, trace2, _, queries2 = _chay(_Model(xin2, _final()), request)
    assert trace2.scope_violations == 1 and queries2.calls == []


# --- 8. lặp lại tất định ---


def test_the_same_inputs_produce_the_same_trace():
    def mot_lan():
        xin = InvestigationResult(
            investigation_id="inv:1", incident_id="inc:1",
            tool_requests=(ToolRequest(tool="get_entity", arguments={"z": 1}),
                           ToolRequest(tool="counts", arguments={"a": 2}),
                           ToolRequest(tool="find_entity", arguments={"m": 3})))
        _, trace, _, queries = _chay(_Model(xin, _final()))
        return json.dumps(trace.to_dict(), sort_keys=True), queries.calls

    a, ca = mot_lan()
    b, cb = mot_lan()
    assert a == b, "vết phải giống nhau"
    assert ca == cb, "thứ tự gọi tool phải giống nhau"
    # Thứ tự tất định, KHÔNG theo thứ tự model đưa ra.
    assert [ten for ten, _ in ca] == ["counts", "find_entity", "get_entity"]


# --- 11. cổng bắt buộc của 3D' ---


@pytest.mark.parametrize("xin", [
    ToolRequest(tool="rm_rf"),
    ToolRequest(tool="isolate_host"),
    ToolRequest(tool="counts", arguments={"incident_id": "inc:KHAC"}),
    ToolRequest(tool="counts", arguments={"window_s": 10 ** 9}),
    ToolRequest(tool="get_entity", arguments={"evidence_ref": "ev:khong_duoc_cap"}),
])
def test_no_unauthorized_or_out_of_scope_tool_is_ever_executed(xin):
    """Model được phép XIN sai. Số lần THỰC THI sai phải bằng 0."""
    result = InvestigationResult(investigation_id="inv:1", incident_id="inc:1",
                                tool_requests=(xin,))
    _, trace, _, queries = _chay(_Model(result, _final()))
    assert trace.executed == 0
    assert queries.calls == []


# --- 12. bất biến kiến trúc ---


def test_the_coordinator_owns_the_loop_and_the_model_owns_nothing():
    import inspect

    import shield.ai.coordinator as C

    nguon = inspect.getsource(C)
    assert "READ_ONLY_TOOLS = " not in nguon, "chỉ một registry tool"
    assert "class CapabilityBroker" not in nguon, "chỉ một broker"
    assert "ResponseJob" not in nguon and "ACTION_SPECS" not in nguon, \
        "3B không chạm tới thực thi hành động"
    assert "self.orchestrator.call_tool" in nguon, \
        "mọi tool phải đi qua điểm thực thi chính sách duy nhất"


def test_the_coordinator_is_on_the_canonical_orchestrator_path():
    from pathlib import Path

    nguon = Path("shield/ai/orchestrator.py").read_text(encoding="utf-8")
    assert "coordinator = Coordinator(self)" in nguon
    assert "coordinator.run(request)" in nguon
    assert nguon.count("self.provider.investigate(") == 0, \
        "orchestrator không được gọi model trực tiếp nữa — Coordinator lái"


def test_no_tool_runs_after_the_token_is_revoked():
    queries = _Queries()
    orch = InvestigationOrchestrator(queries, _Model(_final()))
    token = orch.broker.issue("inc:1", READ_ONLY_TOOLS)
    orch._token, orch._incident_id = token.token, "inc:1"
    orch.broker.revoke(token.token)
    from shield.ai.orchestrator import ToolPolicyViolation

    with pytest.raises(ToolPolicyViolation):
        asyncio.run(orch.call_tool("counts", {}, caller="model"))
    assert queries.calls == []
