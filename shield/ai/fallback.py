"""Phân tích tất định khi lượt điều tra KHÔNG hoàn thành an toàn.

Trước file này, mọi kết thúc bất thường — model nổ, model trả rác, hết vòng,
hết ngân sách tool — đều cho ra cùng một thứ: một `InvestigationResult` rỗng
với đúng một câu lý do. Người vận hành nhận về con số không, đúng lúc họ cần
nhất, và trong khi Shield ĐANG NẮM trong tay toàn bộ dữ liệu chuẩn tắc của
incident đó.

Điều đó không phải an toàn, chỉ là im lặng. Rỗng và "không có gì đáng chú ý"
trông giống hệt nhau trên màn hình.

Nên: khi lượt điều tra hỏng, Shield chạy `LocalDeterministicAnalyst` trên dữ
liệu đã có. Ba ranh giới, và cả ba đều là điều kiện chứ không phải mong muốn:

1. **Không gọi thêm tool.** Fallback chạy SAU khi token đã bị thu hồi, nên
   điều đó không chỉ là quy ước — nó không còn khả thi về mặt cơ chế.
2. **Không đọc một byte nào của output provider.** Đầu vào là request chuẩn
   tắc cộng những quan sát Coordinator đã tự tay thu về. Model có thể đã bịa
   hoàn toàn; bản fallback không hề nhìn thấy thứ nó bịa.
3. **Không nới phạm vi.** Một quan sát chỉ trở thành `fact` khi MỌI
   `evidence_ref` của nó đã nằm trong `allowed_evidence_refs` của lượt điều
   tra. Quan sát là dữ liệu, không phải giấy phép.

Và lý do dừng GỐC được giữ nguyên. `provider_error` + `fallback_used` không
bao giờ được thoái hoá thành `completed`: một provider hỏng liên tục là một
provider cần tắt, và không ai thấy được điều đó nếu mỗi lần hỏng đều được ghi
lại như một lượt bình thường.
"""

from __future__ import annotations

import dataclasses
import json

from shield.ai.contracts import InvestigationRequest, InvestigationResult

# Lý do dừng được phép dùng fallback.
#
# `kill_switch` CỐ Ý không có ở đây — xem `kill_switch_allows_fallback()`.
# `completed` cũng không: đường hoàn thành dùng chính kết quả của provider.
FALLBACK_REASONS = frozenset({
    "max_rounds", "max_tool_calls", "provider_error",
    "malformed_model_output", "timeout", "policy_denied",
})

# Trường của một quan sát được phép trở thành `fact`. Danh sách ĐÓNG, không
# phải "mọi thứ trừ những thứ này": một tool trả về thêm trường mới trong bản
# sau sẽ lặng lẽ đẩy nó vào đầu vào phân tích nếu làm ngược lại.
#
# `src_key`/`dst_key` KHÔNG có mặt: chúng chứa tên file và hostname — dữ liệu
# kẻ tấn công đặt được — và bộ phân tích tất định không cần tới chúng.
_FACT_FIELDS = ("relation", "src_id", "src_type", "dst_id", "dst_type",
                "evidence_refs", "evidence_kind", "trust", "observation_count")

# Trần số fact ghép thêm. Trùng `prompts.MAX_FACTS` có chủ ý: fallback không
# được nhìn thấy nhiều hơn thứ một lượt điều tra bình thường được nhìn thấy.
MAX_OBSERVED_FACTS = 200


def kill_switch_allows_fallback() -> bool:
    """Kill switch có cho phép chạy bản tóm tắt tất định cục bộ không.

    **Không.** Và đây là một quyết định, không phải một giới hạn kỹ thuật.

    `LocalDeterministicAnalyst` là mã tất định: nó không phải model, không gọi
    tool, không cần token, và chạy được khi mọi thứ khác đã tắt. Về mặt kỹ
    thuật nó hoàn toàn an toàn dưới kill switch.

    Nhưng kill switch là công cụ thô của người vận hành, và nó phải có ĐÚNG MỘT
    nghĩa: bật lên thì lớp AI không sinh ra gì cả. Người bật nó đang nghi ngờ
    chính lớp này; giải thích với họ rằng "phần vừa chạy không thật sự là AI"
    là đúng về kỹ thuật và vô dụng lúc 3 giờ sáng. Một công tắc có ngoại lệ là
    một công tắc người ta không dám bật.

    Nên: kill switch -> kết quả rỗng, y như trước. Fallback thuộc về những lần
    hỏng ngoài ý muốn, không thuộc về những lần tắt có chủ ý.
    """
    return False


def observed_facts(request: InvestigationRequest, observations) -> tuple[dict, ...]:
    """Quan sát của Coordinator -> `fact` chuẩn tắc, đã ràng buộc phạm vi.

    Bỏ IM LẶNG mọi dòng không đủ điều kiện. Đây là chỗ duy nhất trong đường
    fallback mà dữ liệu mới đi vào, nên nó đóng chặt: không có `relation` thì
    bộ phân tích không dùng được, và một `evidence_ref` ngoài tập được cấp
    biến cả dòng thành thứ không được xem trong lượt này.
    """
    allowed = request.allowed_evidence_refs
    out: list[dict] = []
    for observation in observations or ():
        if not isinstance(observation, dict):
            continue
        if observation.get("kind") != "tool_observation":
            continue
        for row in observation.get("rows") or ():
            if not isinstance(row, dict) or not row.get("relation"):
                continue
            refs = row.get("evidence_refs")
            if not isinstance(refs, (list, tuple)) or not refs:
                # Không ref thì không phải bằng chứng, và một giả thuyết không
                # có bằng chứng bị validator hạ cấp ngay sau đó.
                continue
            refs = tuple(str(ref) for ref in refs)
            if allowed and not set(refs) <= set(allowed):
                continue
            fact = {key: row[key] for key in _FACT_FIELDS if key in row}
            fact["evidence_refs"] = list(refs)
            out.append(fact)

    # Khử trùng lặp theo nội dung, giữ thứ tự: cùng một cạnh có thể về từ hai
    # tool khác nhau, và đếm nó hai lần là bịa ra một mẫu không có thật.
    unique = dict.fromkeys(json.dumps(fact, sort_keys=True, default=str) for fact in out)
    return tuple(json.loads(key) for key in list(unique)[:MAX_OBSERVED_FACTS])


def fallback_request(request: InvestigationRequest, observations) -> InvestigationRequest:
    """Đầu vào DUY NHẤT của fallback: request chuẩn tắc + quan sát đã lọc.

    Đi qua CHÍNH `facts`, không qua một kênh mới — cùng đường Coordinator dùng
    để đưa quan sát lại cho model. Hai hợp đồng cho cùng một khái niệm nghĩa là
    cái thứ hai sẽ lạc hậu.

    `allowed_evidence_refs` KHÔNG đổi: quan sát không sinh ra quyền mới.
    """
    extra = observed_facts(request, observations)
    if not extra:
        return request
    return dataclasses.replace(request, facts=request.facts + extra)


async def deterministic_fallback(request: InvestigationRequest, observations, *,
                                 analyst=None) -> tuple[InvestigationResult, InvestigationRequest]:
    """Chạy bộ phân tích tất định. -> (kết quả thô, request đã dùng).

    Trả về CẢ request vì mọi tầng kiểm phía sau — `EvidenceValidator`,
    `OutputValidator`, renderer — phải kiểm kết quả này trên đúng tập dữ kiện
    đã sinh ra nó, chứ không phải trên một tập nhỏ hơn.
    """
    from shield.ai.local_provider import LocalDeterministicAnalyst

    canonical = fallback_request(request, observations)
    analyst = analyst or LocalDeterministicAnalyst()
    return await analyst.investigate(canonical), canonical
