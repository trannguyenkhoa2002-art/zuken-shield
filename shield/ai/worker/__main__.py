"""Vỏ worker: hạ trần tài nguyên, đọc một khung, trả một khung, thoát.

**Ở 3C-0 KHÔNG có model thật.** Vỏ này chạy `LocalDeterministicAnalyst` bên
trong tiến trình bị cách ly, và điều đó có chủ ý: nó chứng minh toàn bộ đường
ống — sinh tiến trình, trần tài nguyên, khung truyền, giết, thu hoạch, số liệu
— trên một tải công việc THẬT mà không đưa một byte mã model nào vào. Chỗ nạp
model sau này là đúng một hàm, `_analyse`, và mọi thứ quanh nó đã được test.

Thứ tự trong `main()` là một quyết định an ninh, không phải phong cách:

    hạ trần  ->  đọc khung  ->  phân tích  ->  trả khung

Trần xuống TRƯỚC khi đọc bất cứ thứ gì. Khi mã model được thêm vào, nó được
nạp sau dòng đó — nên mã không đáng tin không bao giờ có một khoảnh khắc nào
chạy với trần chưa hạ.
"""

from __future__ import annotations

import json
import os
import sys

from shield.ai.worker import limits as worker_limits
from shield.ai.worker import netns, protocol
from shield.ai.worker.runtime import RuntimeUnavailable as _RuntimeUnavailable


def _fail(request_id: str, code: str) -> protocol.WorkerResponse:
    return protocol.WorkerResponse(request_id=request_id or "unknown", ok=False,
                                   failure_code=code, result={})


def _emit(response: protocol.WorkerResponse) -> None:
    """Luôn trả về MỘT khung hợp lệ, kể cả khi đang từ chối chạy.

    Im lặng làm agent chờ tới hết giờ, và một lần hết giờ trông giống hệt một
    model treo — nghĩa là người vận hành đọc sai nguyên nhân."""
    try:
        frame = protocol.encode_frame(response.to_payload(),
                                      limit=protocol.MAX_RESPONSE_BYTES)
    except protocol.FrameError:
        frame = protocol.encode_frame(
            _fail(response.request_id, "oversized_response").to_payload(),
            limit=protocol.MAX_RESPONSE_BYTES)
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()


def _read_request(stream) -> protocol.WorkerRequest:
    """Đọc CÓ TRẦN từ agent. Đối xứng với phía kia, và cùng lý do."""
    header = stream.read(protocol.HEADER_BYTES)
    size = protocol.decode_header(header, limit=protocol.MAX_REQUEST_BYTES)
    body = stream.read(size)
    if len(body) != size:
        raise protocol.FrameError("ống đóng giữa khung")
    return protocol.WorkerRequest.parse(protocol.decode_body(body))


def _analyse_with_model(request: protocol.WorkerRequest) -> dict:
    """Chạy model cục bộ. Đây là chỗ DUY NHẤT mã model được nạp.

    Đến dòng này thì trần tài nguyên đã hạ, mạng đã cắt, quyền đã bỏ. Thư viện
    native nạp sau cả ba, có chủ ý: nó là thứ duy nhất ở đây có thể segfault,
    và một segfault trước khi trần xuống là một segfault không bị chặn bởi gì.

    Worker KHÔNG tự kiểm bằng chứng: `EvidenceValidator` sống phía agent, nơi
    có kho bằng chứng. Một worker tự chấm điểm mình là một worker vô dụng.
    """
    from shield.ai.model_config import ModelConfigError, from_environment
    from shield.ai.worker.prompt import build_prompt
    from shield.ai.worker.runtime import (
        RuntimeUnavailable, json_object_grammar, load_runtime, parse_model_output)

    try:
        config = from_environment()
    except ModelConfigError as exc:
        raise RuntimeUnavailable("model_missing", str(exc)) from exc
    if config is None:
        raise RuntimeUnavailable("model_missing", "chưa cấu hình model cục bộ")

    runtime = load_runtime(config)

    if config.mode == "chat":
        # Hỏi đáp gắn vào MỘT sự cố. Cùng ranh giới như `explanation_only`:
        # model chỉ viết văn xuôi, và khung trả lời không có ô nào để nó đụng
        # vào kịch bản, mức nghiêm trọng, ref bằng chứng hay hành động.
        from shield.ai.worker.prompt import build_chat_prompt
        from shield.ai.worker.runtime import chat_grammar

        context = dict(request.facts[0]) if request.facts else {}
        state = str(context.pop("epistemic_state", "") or "UNCONFIRMED")
        question = str(context.pop("question", "") or "")
        history = list(context.pop("history", ()) or ())
        intent = str(context.pop("intent", "") or "")
        # Ý ĐỊNH đã được agent chốt bằng luật tất định. Worker chỉ nhận nhiệm
        # vụ tương ứng — nó không bao giờ được hỏi "câu này hỏi gì", vì đó
        # chính là phép thử phân loại mà model đã trượt.
        if intent:
            from shield.ai.worker.prompt import build_intent_prompt

            prompt = build_intent_prompt(context, intent, history=history,
                                         target_locale=request.target_locale,
                                         state=state)
        else:
            prompt = build_chat_prompt(context, question, history=history,
                                       target_locale=request.target_locale,
                                       state=state)
        text = runtime.generate(prompt, gbnf=chat_grammar())
        parsed = parse_model_output(text, request_id=request.request_id)
        # CHỈ hai ô. Trường lạ bị bỏ ở đây, không đi tiếp để ai đó đọc nhầm.
        return {name: str(parsed.get(name, "") or "")
                for name in ("answer", "limitations")}

    if config.mode == "explanation_only":
        # Vai trò đã chốt của model: chỉ ba ô văn xuôi, cho một kịch bản mà
        # Shield ĐÃ phân loại. Không phân loại, không tool.
        #
        # Nhánh này từng thiếu, và thiếu theo kiểu im lặng: worker vẫn chạy
        # prompt điều tra, trả về một `InvestigationResult` không có khoá
        # `analysis`, và adapter đọc ra ba chuỗi rỗng. Không lỗi nào được ném,
        # không cổng nào chặn — chỉ là văn xuôi không bao giờ xuất hiện.
        from shield.ai.worker.prompt import build_explanation_prompt
        from shield.ai.worker.runtime import explanation_grammar

        context = dict(request.facts[0]) if request.facts else {}
        state = str(context.pop("epistemic_state", "") or "UNCONFIRMED")
        text = runtime.generate(
            build_explanation_prompt(context, target_locale=request.target_locale,
                                     state=state),
            gbnf=explanation_grammar())
        parsed = parse_model_output(text, request_id=request.request_id)
        # CHỈ ba ô. Trường lạ bị bỏ ở đây, không đi tiếp để ai đó đọc nhầm.
        return {name: str(parsed.get(name, "") or "")
                for name in ("analysis", "hypothesis_rationale", "why_this_matters")}

    prompt = build_prompt(request.facts, request.observations,
                          target_locale=request.target_locale)
    # Ngữ pháp cho lượt điều tra: chỉ ràng buộc "phải là MỘT object JSON".
    # Đủ để chặn kiểu hỏng đã đo được trên model 1,5B — bọc JSON trong ```json
    # rồi nói thêm vài câu — mà không ràng buộc nội dung, thứ `contracts.py`
    # đã kiểm kỹ hơn nhiều.
    return parse_model_output(runtime.generate(prompt, gbnf=json_object_grammar()),
                              request_id=request.request_id)


def _analyse_deterministic(request: protocol.WorkerRequest) -> dict:
    """Không có model -> bộ phân tích tất định, VẪN trong tiến trình cách ly.

    Nó không thay `deterministic_fallback` phía agent: cái đó là lưới an toàn
    khi worker không trả lời được. Cái này chứng minh đường ống chạy đúng trên
    một tải công việc thật khi chưa ai cài model — và giữ cho một endpoint
    chưa provision vẫn nói được điều gì đó.
    """
    from shield.ai.contracts import InvestigationRequest
    from shield.ai.local_provider import LocalDeterministicAnalyst

    import asyncio

    canonical = InvestigationRequest(
        investigation_id=request.request_id, incident_id=request.request_id,
        facts=tuple(request.facts) + tuple(request.observations))
    result = asyncio.run(LocalDeterministicAnalyst().investigate(canonical))
    # Chỉ những trường hợp đồng của model cho phép. `summary_key`,
    # `statement_key` KHÔNG đi qua ranh giới này: hợp đồng cấm model chọn khoá
    # i18n, và một worker cũng là model dưới góc nhìn của agent.
    return {
        "investigation_id": request.request_id,
        "incident_id": request.request_id,
        "summary": result.summary,
        "hypotheses": [
            {"id": h.id, "statement": h.statement, "status": h.status,
             "evidence_refs": list(h.evidence_refs),
             "confidence_label": h.confidence_label}
            for h in result.hypotheses
        ],
        "recommended_queries": list(result.recommended_queries),
        "recommended_actions": list(result.recommended_actions),
        "limitations": list(result.limitations),
    }


def _analyse(request: protocol.WorkerRequest) -> dict:
    """Model nếu đã cấu hình, bộ phân tích tất định nếu chưa.

    KHÔNG nuốt lỗi model: một model đã cấu hình mà hỏng phải nổi lên thành
    `runtime_unavailable`/`crashed` và đi tới phương án dự phòng phía agent —
    lặng lẽ thay bằng bản tất định làm một model hỏng liên tục trông y hệt một
    model hoàn hảo.
    """
    from shield.ai.model_config import from_environment

    if from_environment() is None:
        return _analyse_deterministic(request)
    return _analyse_with_model(request)


def main() -> int:
    # DÒNG ĐẦU TIÊN. Mọi thứ sau đây chạy dưới trần đã hạ, kể cả mã model được
    # thêm vào sau này.
    applied: list[str] = []
    try:
        applied = worker_limits.apply(
            worker_limits.ResourceLimits.from_json(
                os.environ.get("SHIELD_WORKER_LIMITS", "{}")))
    except (ValueError, json.JSONDecodeError):
        applied = worker_limits.apply(worker_limits.ResourceLimits())
    # Rồi CẮT MẠNG — trước khi hạ quyền, vì tạo namespace cần CAP_SYS_ADMIN
    # và sau khi bỏ root thì không còn quyền đó nữa. Khi supervisor đã bọc sẵn
    # bằng `bwrap`, biến này không được đặt và ở đây không có gì để làm.
    network = {"isolated": False, "reason": "not_requested"}
    if os.environ.get(netns.NETNS_ENV) == "1":
        network = netns.unshare_network()
        if not network.get("isolated"):
            # Fail closed: worker được yêu cầu chạy không mạng và không làm
            # được. Trả về một khung HỢP LỆ nói đúng điều đó thay vì chạy model
            # có mạng — im lặng ở đây là đúng thứ điều kiện 3C cấm.
            _emit(_fail("", "network_isolation_failed"))
            return 1

    # Rồi HẠ QUYỀN, vẫn trước khi đọc bất cứ thứ gì. `shield-agent.service`
    # chạy `User=root`, nên không làm gì nghĩa là mã model chạy bằng root —
    # và một ranh giới tiến trình chạy bằng root chặn được model ăn RAM nhưng
    # không chặn được model đọc cả máy.
    dropped = worker_limits.drop_privileges()
    print(f"shield-ai-worker: trần={','.join(applied) or 'none'} "
          f"mạng={json.dumps(network, sort_keys=True)} "
          f"quyền={json.dumps(dropped, sort_keys=True)}", file=sys.stderr)

    request_id = ""
    try:
        request = _read_request(sys.stdin.buffer)
        request_id = request.request_id
        response = protocol.WorkerResponse(request_id=request_id, ok=True,
                                           failure_code="ok",
                                           result=_analyse(request))
    except _RuntimeUnavailable as exc:
        # "Chưa cài" và "hỏng" là hai việc khác nhau: cái đầu dẫn tới một dòng
        # hướng dẫn cài, cái sau dẫn tới một cuộc điều tra.
        response = _fail(request_id, exc.code)
    except protocol.FrameError:
        response = _fail(request_id, "malformed_frame")
    except MemoryError:
        # Trần bộ nhớ chạm tới. Nói ra bằng MÃ thay vì chết im lặng: "model quá
        # nặng cho máy này" và "model có lỗi" dẫn tới hai hành động khác nhau.
        response = _fail(request_id, "resource_limit")
    except Exception:  # noqa: BLE001 — mã model là mã không đáng tin
        response = _fail(request_id, "crashed")

    _emit(response)
    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
