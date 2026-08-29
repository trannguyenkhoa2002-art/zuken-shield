"""Điều phối một lượt điều tra (mục 2.3).

Ở Phase 2, orchestrator CHỈ có tool read-only. Nó không import
`shield.privileged` cũng không import `shield.security.response`, và có test đọc
AST để giữ điều đó — một lời hứa trong tài liệu thì lần refactor sau sẽ phá mất.

Ranh giới nó dựng, và lý do:

- **Ngân sách.** Số vòng, số bản ghi mỗi lời gọi, timeout mỗi lời gọi và timeout
  cả lượt. Không có ngân sách thì một model lặp vô hạn sẽ giữ một luồng và một
  kết nối SQLite mãi mãi.
- **Một điểm thực thi chính sách duy nhất.** Mọi tool đi qua `call_tool`. Hai
  đường vào nghĩa là hai bộ kiểm, và bộ thứ hai sẽ lạc hậu.
- **Nhật ký đầy đủ.** Ai gọi, gọi gì, trả về bao nhiêu, mất bao lâu, lỗi gì.
  Ở Phase 2 đây là bằng chứng model đã đọc những gì; ở Phase 5 nó là thứ chứng
  minh một lần prompt injection có hay không vượt được chính sách.
- **Cache theo phiên bản incident.** Phân tích lại một incident không đổi là
  đốt tài nguyên để ra đúng câu trả lời cũ.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
import time
import uuid

from shield.ai.capability import CapabilityBroker, CapabilityDenied, ai_tools_killed
from shield.ai.contracts import InvestigationRequest, InvestigationResult, SchemaViolation
from shield.ai.provider import DisabledProvider
from shield.ai.validator import EvidenceValidator
from shield.ai.coordinator import Coordinator
from shield.ai.redaction import redact

logger = logging.getLogger("shield.ai.orchestrator")

# Tool model được phép gọi. Tất cả đều CHỈ ĐỌC. Danh sách này là chính sách:
# thêm một dòng ở đây là một quyết định về bảo mật, không phải một tiện ích.
READ_ONLY_TOOLS = frozenset({
    "get_entity", "find_entity", "get_neighbors", "get_process_ancestry",
    "get_file_history", "get_user_login_history", "get_network_peers",
    "get_evidence", "get_entity_timeline", "counts",
})

MAX_TOOL_CALLS = 24
MAX_RECORDS_PER_CALL = 100
TOOL_TIMEOUT_S = 5.0
INVESTIGATION_TIMEOUT_S = 60.0
MAX_CONCURRENT_PER_INCIDENT = 1


class ToolPolicyViolation(RuntimeError):
    """Model cố gọi thứ nó không được phép. Đếm riêng, không nuốt."""


class BudgetExceeded(RuntimeError):
    """Hết ngân sách vòng gọi hoặc thời gian."""


class InvestigationOrchestrator:
    def __init__(self, queries, provider=None, *, validator: EvidenceValidator | None = None,
                 max_tool_calls: int = MAX_TOOL_CALLS,
                 tool_timeout_s: float = TOOL_TIMEOUT_S,
                 investigation_timeout_s: float = INVESTIGATION_TIMEOUT_S,
                 broker: CapabilityBroker | None = None) -> None:
        # Broker giữ token; MODEL không bao giờ nhìn thấy token. Đưa token cho
        # model nghĩa là đưa cho nó một thứ để rò rỉ.
        self.broker = broker or CapabilityBroker()
        self._token: str = ""
        self._incident_id: str = ""
        self.queries = queries
        self.provider = provider or DisabledProvider()
        self.validator = validator or EvidenceValidator(queries)
        self.max_tool_calls = max_tool_calls
        self.tool_timeout_s = tool_timeout_s
        self.investigation_timeout_s = investigation_timeout_s
        self.tool_calls: list[dict] = []
        self.policy_violations = 0
        self._locks: dict[str, asyncio.Lock] = {}
        self._cache: dict[str, tuple[str, InvestigationResult, dict]] = {}

    # --- tool ---

    async def call_tool(self, name: str, arguments: dict, *, caller: str = "model") -> list | dict | None:
        """Điểm thực thi chính sách DUY NHẤT. Mọi tool đi qua đây."""
        started = time.monotonic()
        if ai_tools_killed():
            # Kill switch phải chặn TRƯỚC mọi thứ khác, kể cả trước khi kiểm
            # tên tool: người vận hành bật nó vì họ nghi ngờ chính lớp này.
            self.policy_violations += 1
            self._log(name, arguments, 0, time.monotonic() - started, caller,
                      "kill switch AI đang bật")
            raise ToolPolicyViolation("kill switch AI đang bật — mọi tool bị chặn")
        if name not in READ_ONLY_TOOLS:
            # Không nuốt: một lần gọi ngoài chính sách là tín hiệu, và
            # tool-policy violation rate phải bằng 0 trong bộ gate bắt buộc.
            self.policy_violations += 1
            self._log(name, arguments, 0, time.monotonic() - started, caller,
                      "tool không nằm trong chính sách")
            raise ToolPolicyViolation(f"tool không được phép: {name!r}")
        if len(self.tool_calls) >= self.max_tool_calls:
            self._log(name, arguments, 0, time.monotonic() - started, caller, "hết ngân sách")
            raise BudgetExceeded(f"vượt {self.max_tool_calls} lời gọi tool")

        if self._token:
            # Có token nghĩa là đang trong một lượt điều tra. Ngoài lượt điều
            # tra, `call_tool` vẫn dùng được cho mã của chính Shield — nhưng
            # mọi lời gọi CỦA MODEL đều đi qua đây với token.
            try:
                self.broker.check(self._token, name, self._incident_id)
            except CapabilityDenied as exc:
                self.policy_violations += 1
                self._log(name, arguments, 0, time.monotonic() - started, caller, str(exc))
                raise ToolPolicyViolation(str(exc)) from exc

        method = getattr(self.queries, name, None)
        if method is None:
            self.policy_violations += 1
            self._log(name, arguments, 0, time.monotonic() - started, caller, "tool không tồn tại")
            raise ToolPolicyViolation(f"tool không tồn tại: {name!r}")

        safe = dict(arguments or {})
        if "limit" in safe:
            safe["limit"] = min(int(safe.get("limit") or MAX_RECORDS_PER_CALL),
                                MAX_RECORDS_PER_CALL)
        try:
            result = await asyncio.wait_for(asyncio.to_thread(method, **safe),
                                            self.tool_timeout_s)
        except TimeoutError as exc:
            self._log(name, safe, 0, time.monotonic() - started, caller, "hết thời gian")
            raise BudgetExceeded(f"tool {name} hết thời gian") from exc
        except TypeError as exc:
            # Tham số sai KHÔNG được coi là lỗi hệ thống: nó là model gọi sai,
            # và phải đếm như một lần vi phạm chứ không phải một lần Shield hỏng.
            self.policy_violations += 1
            self._log(name, safe, 0, time.monotonic() - started, caller, f"tham số sai: {exc}")
            raise ToolPolicyViolation(f"tham số không hợp lệ cho {name}: {exc}") from exc

        rows = len(result) if isinstance(result, list) else (0 if result is None else 1)
        self._log(name, safe, rows, time.monotonic() - started, caller, "")
        return result

    def _log(self, name: str, arguments: dict, rows: int, elapsed: float,
             caller: str, error: str) -> None:
        self.tool_calls.append({
            "tool": name,
            # Redaction ở tầng nhật ký nữa, không chỉ ở tầng query: đối số cũng
            # có thể chứa bí mật, và nhật ký sống lâu hơn kết quả.
            "arguments": redact(arguments),
            "rows": rows, "elapsed_s": round(elapsed, 6), "caller": caller,
            "provider": getattr(self.provider, "name", "?"),
            "ts": time.time(), "error": error,
        })
        if len(self.tool_calls) > 500:
            del self.tool_calls[: len(self.tool_calls) - 500]

    # --- điều tra ---

    async def investigate(self, request: InvestigationRequest) -> tuple[InvestigationResult, dict]:
        """Chạy một lượt điều tra. KHÔNG BAO GIỜ ném ra ngoài.

        Đây là bất biến của gate Phase 2: "Tắt AI không làm giảm detection hiện
        có" và "Model lỗi/timeout/sai schema thì pipeline detection vẫn chạy".
        Một ngoại lệ thoát khỏi đây sẽ đi ngược lên vòng lặp alert của agent, và
        khi đó AI trở thành nguyên nhân làm hỏng detection — đúng thứ cấm.
        """
        lock = self._locks.setdefault(request.incident_id, asyncio.Lock())
        if lock.locked():
            # Một lượt điều tra cho mỗi incident tại một thời điểm. Không có
            # giới hạn này thì một incident ồn ào sẽ mở hàng chục lượt song song.
            return self._empty(request, "đã có một lượt điều tra đang chạy cho incident này"), {}

        async with lock:
            fingerprint = self._fingerprint(request)
            cached = self._cache.get(request.incident_id)
            if cached and cached[0] == fingerprint:
                return cached[1], cached[2]

            if ai_tools_killed():
                return self._empty(request, "kill switch AI đang bật"), {}
            try:
                token = self.broker.issue(request.incident_id, READ_ONLY_TOOLS,
                                          tool_budget=self.max_tool_calls)
            except CapabilityDenied as exc:
                return self._empty(request, str(exc)), {}
            self._token, self._incident_id = token.token, request.incident_id

            started = time.monotonic()
            # try/finally, KHÔNG phải thu hồi ở cuối đường thành công: model
            # timeout, model nổ, model trả rác — cả ba đều thoát sớm, và mỗi
            # lần thoát sớm mà không thu hồi là một token còn sống mà không ai
            # nhớ. Một token còn sống là một quyền còn dùng được.
            # Coordinator dựng TRƯỚC `wait_for` chứ không dựng lồng trong nó:
            # khi đồng hồ tổng huỷ `run`, giá trị trả về không bao giờ tới nơi,
            # nhưng những quan sát đã thu hợp lệ vẫn nằm trên instance này —
            # và đó là thứ phương án dự phòng tất định đọc.
            coordinator = Coordinator(self)
            raw = None
            try:
                try:
                    # Phase 3B: Coordinator lái vòng lặp. Model XIN đọc thêm,
                    # Coordinator GỌI — và `call_tool` vẫn là điểm thực thi
                    # chính sách duy nhất, không đổi một dòng.
                    #
                    # Timeout bọc CẢ vòng lặp, không bọc từng lượt gọi model:
                    # một model xin tool mãi mãi phải chết vì đồng hồ tổng, chứ
                    # không phải chạy vô hạn với mỗi lượt đều kịp giờ.
                    raw, _ = await asyncio.wait_for(
                        coordinator.run(request), self.investigation_timeout_s)
                except TimeoutError:
                    coordinator.trace.termination_reason = "timeout"
                except SchemaViolation:
                    coordinator.trace.termination_reason = "malformed_model_output"
                except Exception as exc:  # noqa: BLE001 — model là mã không đáng tin
                    logger.warning("Provider %s lỗi: %s",
                                   getattr(self.provider, "name", "?"), exc)
                    coordinator.trace.termination_reason = "provider_error"
                    coordinator.trace.provider_error_type = type(exc).__name__
            finally:
                # Thu hồi TRƯỚC phương án dự phòng, có chủ ý: từ dòng này trở
                # đi không còn tool nào gọi được nữa, nên "fallback không gọi
                # thêm tool" là một bất khả thi về cơ chế, không phải một lời
                # hứa trong tài liệu.
                self.broker.revoke(self._token)
                self._token = ""

            trace = coordinator.trace
            if not isinstance(raw, InvestigationResult) or trace.termination_reason != "completed":
                # Không hoàn thành an toàn. `max_rounds` và `max_tool_calls`
                # cũng vào đây dù `raw` là một kết quả hợp lệ: kết quả đó là
                # bản NỬA CHỪNG của một model còn đang xin đọc thêm, và trình
                # bày nó như một kết luận là nói rằng model đã xong.
                return await self._fallback(request, coordinator, started)

            validated, report = self.validator.validate(raw, request)
            validated = self._finalise(validated, started)
            payload = report.to_dict()
            if trace is not None:
                payload["coordinator"] = trace.to_dict()
                payload["termination_reason"] = trace.termination_reason
            payload["tool_calls"] = len(self.tool_calls)
            payload["policy_violations"] = self.policy_violations
            payload["capability_denials"] = self.broker.denials
            self._cache[request.incident_id] = (fingerprint, validated, payload)
            if len(self._cache) > 256:
                self._cache.pop(next(iter(self._cache)))
            return validated, payload

    # --- phương án dự phòng tất định ---

    # Lý do dừng -> câu nói với người vận hành. Phải khớp MÃ dừng của
    # Coordinator, không thoái hoá thành một câu chung: "model nổ" và "model
    # trả rác" là hai việc khác nhau với người phải quyết định có tắt nó không.
    _FALLBACK_TEXT = {
        "provider_error": "model lỗi: {error_type}",
        "malformed_model_output": "model trả về sai schema",
        "timeout": "model hết thời gian",
        "max_rounds": "model không kết luận sau {rounds} vòng",
        "max_tool_calls": "model dùng hết ngân sách đọc bằng chứng",
        "policy_denied": "model bị từ chối quyền cần cho lượt điều tra này",
        "kill_switch": "kill switch AI đang bật",
    }

    async def _fallback(self, request: InvestigationRequest, coordinator,
                        started: float) -> tuple[InvestigationResult, dict]:
        """Lượt điều tra hỏng -> phân tích tất định từ dữ liệu đã có.

        Không đọc một byte nào của output provider: đầu vào là request chuẩn
        tắc cộng những quan sát Coordinator đã TỰ thu về và đã ràng buộc phạm
        vi. Model có thể đã bịa hoàn toàn; bản này không nhìn thấy thứ nó bịa.
        """
        from shield.ai.fallback import (
            FALLBACK_REASONS, deterministic_fallback, kill_switch_allows_fallback)

        trace = coordinator.trace
        reason = trace.termination_reason
        ly_do = self._FALLBACK_TEXT.get(reason, "model trả về kiểu không hợp lệ").format(
            error_type=trace.provider_error_type or "Exception", rounds=trace.rounds)

        cho_phep = reason in FALLBACK_REASONS or (
            reason == "kill_switch" and kill_switch_allows_fallback())
        if not cho_phep:
            return self._empty(request, ly_do), {
                "coordinator": trace.to_dict(), "termination_reason": reason,
                "fallback_used": False, "deterministic_fallbacks": 0,
            }

        try:
            raw, canonical = await deterministic_fallback(
                request, coordinator.observations)
        except Exception:  # noqa: BLE001
            # Phương án dự phòng hỏng KHÔNG được trở thành ngoại lệ thoát ra:
            # đây là đường chạy khi mọi thứ khác đã hỏng, và nó là chỗ cuối
            # cùng được phép làm hỏng vòng lặp alert.
            logger.exception("Phân tích tất định dự phòng lỗi")
            return self._empty(request, ly_do), {
                "coordinator": trace.to_dict(), "termination_reason": reason,
                "fallback_used": False, "deterministic_fallbacks": 0,
            }

        trace.deterministic_fallbacks += 1
        validated, report = self.validator.validate(raw, canonical)
        validated = dataclasses.replace(
            validated,
            # `errors` giữ nguyên lý do GỐC. Một lượt dự phòng không bao giờ
            # được đọc như một lượt bình thường — nếu nó được, thì một provider
            # hỏng liên tục trông y hệt một provider hoàn hảo.
            errors=(ly_do,),
            limitations=validated.limitations + (
                f"Lượt điều tra không hoàn thành ({reason}); đây là phân tích "
                "tất định cục bộ trên dữ liệu đã thu được, không phải kết luận "
                "của model.",),
            limitation_keys=validated.limitation_keys + ("ai.fallback.limitation",),
        )
        validated = self._finalise(validated, started)

        payload = report.to_dict()
        payload["coordinator"] = trace.to_dict()
        payload["termination_reason"] = reason
        payload["fallback_used"] = True
        payload["deterministic_fallbacks"] = trace.deterministic_fallbacks
        payload["observed_facts"] = len(canonical.facts) - len(request.facts)
        payload["tool_calls"] = len(self.tool_calls)
        payload["policy_violations"] = self.policy_violations
        payload["capability_denials"] = self.broker.denials
        # KHÔNG vào cache: cache là để khỏi phân tích lại một incident không
        # đổi. Một lượt hỏng thì lần sau phải được thử lại — ghim kết quả dự
        # phòng nghĩa là một lỗi provider thoáng qua khoá luôn incident đó.
        return validated, payload

    def _finalise(self, result: InvestigationResult, started: float) -> InvestigationResult:
        return dataclasses.replace(
            result,
            analysed_ts=time.time(),
            limitations=result.limitations + (
                f"Phân tích trong {time.monotonic() - started:.2f}s với "
                f"{len(self.tool_calls)} lời gọi tool.",
            ),
        )

    @staticmethod
    def _fingerprint(request: InvestigationRequest) -> str:
        """Vân tay của đầu vào. Incident không đổi thì không phân tích lại."""
        import json

        payload = json.dumps(request.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _empty(self, request: InvestigationRequest, reason: str) -> InvestigationResult:
        return InvestigationResult(
            investigation_id=request.investigation_id or uuid.uuid4().hex,
            incident_id=request.incident_id,
            summary="",
            limitations=(reason,),
            errors=(reason,),
            provider=getattr(self.provider, "name", "?"),
            analysed_ts=time.time(),
        )
