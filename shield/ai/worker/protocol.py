"""Khung truyền và lược đồ giữa agent và worker model.

Ba quyết định, cả ba đều là quyết định an ninh:

1. **Length-prefixed, KHÔNG phải readline.** Một worker thù địch chỉ cần phun
   một dòng không bao giờ kết thúc là `readline()` ăn hết RAM của agent — và
   `StreamReader.readline()` giữ nguyên dữ liệu đã đọc trong bộ đệm khi vượt
   `limit`. Với tiền tố độ dài, agent biết phải đọc bao nhiêu TRƯỚC khi đọc, và
   một con số quá lớn bị từ chối mà không cấp phát một byte nào.

2. **JSON, KHÔNG BAO GIỜ pickle.** `pickle.loads` trên dữ liệu từ một tiến
   trình không đáng tin là thực thi mã tuỳ ý — đúng thứ ranh giới này dựng ra
   để chặn. Không `marshal`, không `shelve`, không `__reduce__`.

3. **Fail closed.** Khung sai, độ dài sai, JSON sai, `request_id` lệch, phiên
   bản lược đồ lạ — tất cả đều là lỗi, không có đường "đoán ý". Một khung nửa
   hợp lệ được nhận một nửa nghĩa là phần bị bỏ qua chính là phần bất thường
   nhất.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field

# Phiên bản lược đồ. Đổi hình dạng khung là đổi số này — hai bên kiểm nhau, và
# một worker cũ nói chuyện với agent mới phải HỎNG TO chứ không im lặng gửi
# thiếu trường.
SCHEMA_VERSION = 1

# Tiền tố độ dài: 4 byte big-endian không dấu, rồi đúng bấy nhiêu byte JSON.
_HEADER = struct.Struct("!I")
HEADER_BYTES = _HEADER.size

# Trần cứng, ở CẢ HAI chiều. Không đọc từ cấu hình người dùng: một trần có thể
# nới bằng biến môi trường là một trần kẻ tấn công nới được.
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

_REQUEST_ID = re.compile(r"^[A-Za-z0-9_:-]{1,64}$")
_LOCALE = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")

# Mã lỗi ĐÓNG. Người vận hành đếm được, so được giữa hai lần chạy, và không có
# câu văn nào do worker sinh lọt vào chỗ này.
FAILURE_CODES = frozenset({
    "ok", "timeout", "crashed", "resource_limit", "malformed_frame",
    "oversized_response", "worker_exit", "pipe_closed", "spawn_failed",
    "kill_switch", "busy", "protocol_mismatch",
    # Phase 3C: model chạy TRONG worker, nên hai cách hỏng mới xuất hiện —
    # không cắt được mạng, và runtime/model không có mặt. Cả hai là lý do TỪ
    # CHỐI chạy, không phải lý do chạy kém.
    "network_isolation_failed", "runtime_unavailable", "model_missing",
    # Phase 3C-1: không dựng được cgroup scope anh em. Đây là lý do TỪ CHỐI
    # chạy model, không phải một lỗi lúc chạy.
    "scope_unavailable",
})


class FrameError(ValueError):
    """Khung không hợp lệ. Fail closed — không đoán, không cắt gọt."""


def encode_frame(payload: dict, *, limit: int) -> bytes:
    """dict -> khung. Vượt trần thì ném ở phía GỬI, không đẩy sang bên kia."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    if len(body) > limit:
        raise FrameError(f"khung {len(body)} byte vượt trần {limit}")
    return _HEADER.pack(len(body)) + body


def decode_header(header: bytes, *, limit: int) -> int:
    """4 byte đầu -> độ dài thân, đã kiểm trần.

    Kiểm TRƯỚC khi đọc thân là toàn bộ giá trị của tiền tố độ dài: một worker
    khai báo 4 GiB bị từ chối mà agent chưa cấp phát byte nào.
    """
    if len(header) != HEADER_BYTES:
        raise FrameError("thiếu tiền tố độ dài")
    (size,) = _HEADER.unpack(header)
    if size == 0:
        raise FrameError("khung rỗng")
    if size > limit:
        raise FrameError(f"khung khai báo {size} byte, vượt trần {limit}")
    return size


def decode_body(body: bytes) -> dict:
    if not isinstance(body, (bytes, bytearray)):
        raise FrameError("thân khung phải là byte")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrameError(f"thân khung không phải JSON hợp lệ: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise FrameError("thân khung phải là một object JSON")
    return payload


@dataclass(frozen=True)
class WorkerRequest:
    """Thứ DUY NHẤT worker được thấy.

    Không có DB handle, không `CapabilityToken`, không tool registry, không
    đường dẫn tuỳ ý. Nếu một trường nào đó không có mặt ở đây thì worker không
    có cách nào biết tới nó — đó là điểm của việc liệt kê đóng.
    """

    request_id: str
    facts: tuple[dict, ...] = ()
    observations: tuple[dict, ...] = ()
    target_locale: str = "vi"
    deadline_s: float = 30.0
    schema_version: int = SCHEMA_VERSION

    def to_payload(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION, "kind": "request",
            "request_id": self.request_id,
            "facts": [dict(f) for f in self.facts],
            "observations": [dict(o) for o in self.observations],
            "target_locale": self.target_locale,
            "deadline_s": float(self.deadline_s),
        }

    @classmethod
    def parse(cls, payload: dict) -> "WorkerRequest":
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise FrameError(f"phiên bản lược đồ lạ: {payload.get('schema_version')!r}")
        if payload.get("kind") != "request":
            raise FrameError("khung không phải một yêu cầu")
        unknown = set(payload) - {"schema_version", "kind", "request_id", "facts",
                                  "observations", "target_locale", "deadline_s"}
        if unknown:
            raise FrameError(f"yêu cầu có trường lạ: {sorted(unknown)}")
        request_id = str(payload.get("request_id", ""))
        if not _REQUEST_ID.match(request_id):
            raise FrameError(f"request_id không hợp lệ: {request_id!r}")
        locale = str(payload.get("target_locale", "vi"))
        if not _LOCALE.match(locale):
            raise FrameError(f"target_locale không hợp lệ: {locale!r}")
        for name in ("facts", "observations"):
            value = payload.get(name) or []
            if not isinstance(value, list) or any(not isinstance(i, dict) for i in value):
                raise FrameError(f"{name} phải là danh sách object")
        return cls(
            request_id=request_id,
            facts=tuple(dict(f) for f in payload.get("facts") or ()),
            observations=tuple(dict(o) for o in payload.get("observations") or ()),
            target_locale=locale,
            deadline_s=float(payload.get("deadline_s", 30.0)),
        )


@dataclass(frozen=True)
class WorkerResponse:
    """Thứ worker được phép nói. Nghiêm ngặt như hợp đồng của model ở 3A.

    `result` đi tiếp tới `InvestigationResult.parse` — nên ở tầng này chỉ cần
    khẳng định nó là một object JSON có kích thước hữu hạn. Ranh giới tiến
    trình không thay việc kiểm nội dung; nó chỉ bảo đảm việc kiểm ấy CÓ CƠ HỘI
    chạy, thay vì chết cùng agent.
    """

    request_id: str
    ok: bool = True
    failure_code: str = "ok"
    result: dict = field(default_factory=dict)

    def to_payload(self) -> dict:
        return {"schema_version": SCHEMA_VERSION, "kind": "response",
                "request_id": self.request_id, "ok": bool(self.ok),
                "failure_code": self.failure_code, "result": dict(self.result)}

    @classmethod
    def parse(cls, payload: dict, *, expect_id: str) -> "WorkerResponse":
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise FrameError(f"phiên bản lược đồ lạ: {payload.get('schema_version')!r}")
        if payload.get("kind") != "response":
            raise FrameError("khung không phải một phản hồi")
        unknown = set(payload) - {"schema_version", "kind", "request_id", "ok",
                                  "failure_code", "result"}
        if unknown:
            raise FrameError(f"phản hồi có trường lạ: {sorted(unknown)}")
        if str(payload.get("request_id", "")) != expect_id:
            # Lệch `request_id` nghĩa là đang đọc phản hồi của một yêu cầu
            # KHÁC. Nhận nó là gán kết luận của lượt này cho dữ liệu lượt kia.
            raise FrameError("request_id của phản hồi không khớp")
        code = str(payload.get("failure_code", "ok"))
        if code not in FAILURE_CODES:
            raise FrameError(f"failure_code ngoài danh sách: {code!r}")
        result = payload.get("result") or {}
        if not isinstance(result, dict):
            raise FrameError("result phải là một object JSON")
        return cls(request_id=expect_id, ok=bool(payload.get("ok", False)),
                   failure_code=code, result=result)
