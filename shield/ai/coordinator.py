"""Coordinator: vòng lặp đọc bằng chứng, và Shield giữ vô lăng (Phase 3B).

Trước file này, một lượt điều tra là MỘT lời gọi model: `provider.investigate()`
nhận request rồi trả kết luận. `call_tool()` đã tồn tại và đã kiểm chính sách
đầy đủ, nhưng không có gì lái nó — nên model không bao giờ đọc thêm được gì.

Cho model đọc thêm là thứ làm nó hữu ích, và cũng là thứ nguy hiểm nhất có thể
thêm vào. Nên ranh giới ở đây tuyệt đối: **model XIN, Coordinator GỌI.**

Model không sở hữu: registry tool, quota, phạm vi, timeout, thứ tự thực thi,
hay vòng lặp. Nó chỉ phát ra `ToolRequest` — tên tool và các giá trị đơn — và
mọi thứ khác do máy trạng thái này quyết định.

Quan sát trả về model đi qua CHÍNH `InvestigationRequest.facts`, không qua một
kênh mới: quan sát cũng là telemetry, và `facts` từ đầu đã là "telemetry có
kiểu đưa cho model". Không thêm hợp đồng thứ hai cho cùng một khái niệm.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time

from shield.ai.capability import CapabilityDenied, ai_tools_killed
from shield.ai.contracts import InvestigationRequest, InvestigationResult, SchemaViolation
from shield.ai.redaction import redact

logger = logging.getLogger("shield.ai.coordinator")

# Trần vòng lặp. `MAX_TOOL_CALLS = 24` và `MAX_TOOL_REQUESTS = 4` mỗi lượt, nên
# 6 vòng vừa đủ tiêu hết ngân sách tool mà không nhiều hơn: một trần vòng lặp
# lớn hơn ngân sách tool chỉ tạo ra những vòng không làm gì.
MAX_ROUNDS = 6

# Lý do dừng, dạng MÃ. Một câu văn thì không đếm được, không đưa vào
# MetricsReport được, và không so được giữa hai lần chạy.
TERMINATION_REASONS = frozenset({
    "completed", "max_rounds", "max_tool_calls", "timeout",
    "malformed_model_output", "policy_denied", "provider_error",
    "kill_switch", "fallback",
})

# Đối số mang nghĩa "phạm vi". Model không được mở rộng chúng.
_SCOPE_INCIDENT_KEYS = ("incident_id", "incident")
_SCOPE_TIME_KEYS = ("since", "until", "start_ts", "end_ts", "from_ts", "to_ts")


class ScopeViolation(RuntimeError):
    """Model xin ra ngoài phạm vi được cấp. Từ chối, không cắt gọt."""


def _canonical(request) -> str:
    """Khoá sắp thứ tự tất định cho một ToolRequest.

    Thứ tự thực thi KHÔNG được phụ thuộc thứ tự khoá trong dict model trả về:
    hai lần chạy cùng đầu vào phải cho cùng một vết.
    """
    return json.dumps({"tool": request.tool, "arguments": request.arguments},
                      sort_keys=True, default=str)


@dataclasses.dataclass
class CoordinatorTrace:
    """Vết tất định của một lượt. Mã và số, không có câu văn."""

    rounds: int = 0
    termination_reason: str = "completed"
    steps: list = dataclasses.field(default_factory=list)
    unauthorized_tool_calls: int = 0
    tool_denials: int = 0
    tool_timeouts: int = 0
    malformed_tool_requests: int = 0
    scope_violations: int = 0
    deterministic_fallbacks: int = 0
    executed: int = 0
    # Chỉ TÊN KIỂU của ngoại lệ, không phải thông điệp: thông điệp do mã model
    # sinh ra và có thể chứa bất cứ thứ gì, kể cả bí mật nó vừa đọc.
    provider_error_type: str = ""

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data["steps"] = list(self.steps)
        return data


class Coordinator:
    """Máy trạng thái. Nó sở hữu vòng lặp; model chỉ được xin."""

    def __init__(self, orchestrator, *, max_rounds: int = MAX_ROUNDS) -> None:
        self.orchestrator = orchestrator
        self.max_rounds = max(1, int(max_rounds))
        # Vết và quan sát nằm trên INSTANCE, không chỉ là biến cục bộ của
        # `run`. Lý do: `run` có thể bị huỷ giữa chừng bởi đồng hồ tổng của
        # orchestrator, và khi đó giá trị trả về không bao giờ tới nơi. Những
        # gì đã thu được hợp lệ trước lúc bị huỷ vẫn là dữ liệu thật, và
        # phương án dự phòng tất định cần đọc được chúng.
        self.trace = CoordinatorTrace()
        self.observations: tuple[dict, ...] = ()

    # --- ràng buộc phạm vi ---

    def _bind_scope(self, request: InvestigationRequest, tool_request) -> dict:
        """Đối số đã ràng buộc, hoặc `ScopeViolation`.

        TỪ CHỐI thay vì cắt gọt. Cắt một cửa sổ thời gian rồi vẫn trả kết quả
        nghĩa là model nhận về câu trả lời cho một câu hỏi KHÁC câu nó đặt, mà
        nó không được biết — và nó sẽ kết luận trên nền đó.
        """
        arguments = dict(tool_request.arguments)
        for key in _SCOPE_INCIDENT_KEYS:
            if key in arguments and str(arguments[key]) != str(request.incident_id):
                raise ScopeViolation(
                    f"{key} khác incident của lượt điều tra")
        for key in _SCOPE_TIME_KEYS:
            if key not in arguments:
                continue
            try:
                value = float(arguments[key])
            except (TypeError, ValueError) as exc:
                raise ScopeViolation(f"{key} không phải mốc thời gian") from exc
            if value < 0:
                raise ScopeViolation(f"{key} âm")
        if "window_s" in arguments:
            try:
                window = float(arguments["window_s"])
            except (TypeError, ValueError) as exc:
                raise ScopeViolation("window_s không phải số") from exc
            if window > float(request.window_s):
                raise ScopeViolation(
                    f"window_s {window} vượt cửa sổ {request.window_s} của lượt điều tra")
        # Ref bằng chứng: chỉ được hỏi thứ đã được cấp.
        for key, value in arguments.items():
            if "ref" in key and request.allowed_evidence_refs:
                if str(value) not in request.allowed_evidence_refs:
                    raise ScopeViolation(f"{key} nằm ngoài tập bằng chứng được cấp")
        return arguments

    # --- quan sát ---

    @staticmethod
    def _observation(tool: str, round_index: int, result) -> dict:
        """Kết quả tool -> một `fact` có kiểu, có giới hạn, đã che bí mật.

        Đi qua `redact` chung, và KHÔNG mang theo đối tượng nào — chỉ giá trị.
        """
        from shield.ai.orchestrator import MAX_RECORDS_PER_CALL

        if isinstance(result, list):
            rows = [redact(item) for item in result[:MAX_RECORDS_PER_CALL]]
        elif result is None:
            rows = []
        else:
            rows = [redact(result)]
        return {
            "kind": "tool_observation",
            "tool": str(tool),
            "round": int(round_index),
            "row_count": len(rows),
            "rows": rows,
        }

    # --- vòng lặp ---

    async def run(self, request: InvestigationRequest):
        """-> (kết quả, vết). KHÔNG ném ra ngoài trừ khi orchestrator bắt."""
        self.trace = trace = CoordinatorTrace()
        self.observations = observations = ()
        result: InvestigationResult | None = None

        for round_index in range(self.max_rounds):
            trace.rounds = round_index + 1
            if ai_tools_killed():
                trace.termination_reason = "kill_switch"
                return result, trace

            current = (request if not observations
                       else dataclasses.replace(request,
                                                facts=request.facts + observations))
            try:
                result = await self.orchestrator.provider.investigate(current)
            except SchemaViolation:
                trace.termination_reason = "malformed_model_output"
                return result, trace
            except Exception as exc:  # noqa: BLE001 — model là mã không đáng tin
                trace.termination_reason = "provider_error"
                trace.provider_error_type = type(exc).__name__
                return result, trace

            if not isinstance(result, InvestigationResult):
                trace.termination_reason = "malformed_model_output"
                return None, trace

            if not result.tool_requests:
                trace.termination_reason = "completed"
                return result, trace

            # Thứ tự tất định, không theo thứ tự model đưa ra.
            wanted = sorted(result.tool_requests, key=_canonical)
            for tool_request in wanted:
                if len(self.orchestrator.tool_calls) >= self.orchestrator.max_tool_calls:
                    trace.termination_reason = "max_tool_calls"
                    return result, trace
                buoc = await self._one_call(request, tool_request, round_index, trace)
                if buoc is not None:
                    # Ghi vào instance NGAY, không gom tới cuối vòng: mỗi
                    # đường thoát sớm ở giữa vòng — hết ngân sách, bị huỷ vì
                    # đồng hồ tổng — là một lần những quan sát đã thu hợp lệ
                    # biến mất, và chúng là thứ phương án dự phòng sống nhờ.
                    observations = self.observations = observations + (buoc,)

        trace.termination_reason = "max_rounds"
        return result, trace

    async def _one_call(self, request, tool_request, round_index, trace):
        """Một lời gọi. Mọi đường thoát đều ghi vết."""
        from shield.ai.orchestrator import BudgetExceeded, ToolPolicyViolation

        buoc = {"round": round_index, "tool": tool_request.tool,
                "intent": tool_request.intent, "executed": False, "outcome": "",
                "rows": 0}
        try:
            arguments = self._bind_scope(request, tool_request)
        except ScopeViolation as exc:
            trace.scope_violations += 1
            trace.tool_denials += 1
            buoc["outcome"] = "scope_violation"
            trace.steps.append(buoc)
            logger.warning("Từ chối tool %r ngoài phạm vi: %s", tool_request.tool, exc)
            return None

        try:
            result = await self.orchestrator.call_tool(
                tool_request.tool, arguments, caller="model")
        except ToolPolicyViolation:
            # `call_tool` đã đếm `policy_violations` và đã ghi nhật ký. Ở đây chỉ
            # phân loại cho MetricsReport.
            trace.unauthorized_tool_calls += 1
            trace.tool_denials += 1
            buoc["outcome"] = "policy_denied"
            trace.steps.append(buoc)
            return None
        except CapabilityDenied:
            trace.tool_denials += 1
            buoc["outcome"] = "capability_denied"
            trace.steps.append(buoc)
            return None
        except BudgetExceeded as exc:
            if "hết thời gian" in str(exc):
                trace.tool_timeouts += 1
                buoc["outcome"] = "timeout"
            else:
                buoc["outcome"] = "budget_exceeded"
            trace.steps.append(buoc)
            return None
        except Exception:  # noqa: BLE001 — tool chạy trên dữ liệu thật
            buoc["outcome"] = "tool_error"
            trace.steps.append(buoc)
            logger.exception("Tool %r lỗi", tool_request.tool)
            return None

        quan_sat = self._observation(tool_request.tool, round_index, result)
        buoc.update(executed=True, outcome="ok", rows=quan_sat["row_count"])
        trace.executed += 1
        trace.steps.append(buoc)
        return quan_sat
