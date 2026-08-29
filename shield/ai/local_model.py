"""Adapter model cục bộ — implement `AnalystModel` đã có (Phase 3C).

KHÔNG có vũ trụ provider thứ hai. `AnalystModel` là một Protocol với đúng một
phương thức, và file này chỉ thêm một lớp thoả nó. Mọi thứ phía sau —
Coordinator, `EvidenceValidator`, `OutputValidator`, renderer, audit, phương án
dự phòng tất định — không đổi một dòng.

Luồng dữ liệu, và ranh giới ở mỗi mũi tên:

    Coordinator                     (vòng lặp tool ở LẠI đây)
      -> LocalModelAnalyst          (file này: dựng WorkerRequest)
        -> WorkerSupervisor         (trần tài nguyên + netns rỗng + giết/thu)
          -> khung length-prefixed  (JSON, có phiên bản, không pickle)
            -> worker               (model nạp Ở ĐÂY, sau khi đã cắt hết)

Thứ đi qua mũi tên thứ ba là `facts`, `observations`, `target_locale`,
`request_id`. Không `CapabilityToken`, không DB handle, không tool registry,
không đường dẫn. Worker không biết `READ_ONLY_TOOLS` tồn tại — nó chỉ có thể
XIN, và Coordinator quyết định.

Mọi cách hỏng đều ném ra ngoài, có chủ ý: Coordinator bắt và ghi mã dừng, rồi
`InvestigationOrchestrator._fallback` chạy bộ phân tích tất định trên chính dữ
liệu đã có. Nuốt lỗi ở đây sẽ biến một model hỏng thành một model im lặng, và
im lặng là dạng hỏng khó phát hiện nhất.
"""

from __future__ import annotations

import logging

from shield.ai.contracts import InvestigationRequest, InvestigationResult, SchemaViolation
from shield.ai.model_config import ModelConfig, from_environment
from shield.ai.worker import protocol
from shield.ai.worker.limits import ResourceLimits
from shield.ai.worker.supervisor import WorkerFailure, WorkerSupervisor

logger = logging.getLogger("shield.ai.local_model")

# Quan sát do Coordinator thu về đi qua CHÍNH `request.facts` từ Phase 3B. Tách
# chúng ra lại ở đây để worker thấy đúng hai khối như hợp đồng khung mô tả —
# không thêm một kênh thứ hai cho cùng một khái niệm.
_OBSERVATION_KIND = "tool_observation"

# Trần cgroup cho scope model. Chọn TỪ SỐ ĐO, không phải từ "4 GiB thì nạp được".
#
#   VmRSS đỉnh quan sát được   2014 MiB  (chặn trên: mọi trang đã ánh xạ)
#   cgroup memory.peak         934 MiB   (page cache của GGUF do người khác giữ)
#   -> 2560 MiB = chặn trên + ~27% biên
#
# Lấy chặn TRÊN chứ không lấy 934 MiB, vì lần chạy nguội đầu tiên chính cgroup
# này sẽ phải nạp trang GGUF và bị tính đủ.
SCOPE_MEMORY_MAX = "2560M"
# 3 lõi trên máy 12 lõi: model được chạy, collector không bị đói. Con số này
# đi cùng `ModelConfig.threads` — cấp quota cho nhiều lõi hơn số luồng chỉ tạo
# ảo giác rộng rãi.
SCOPE_CPU_QUOTA = "300%"
SCOPE_TASKS_MAX = "96"


class LocalModelAnalyst:
    """`AnalystModel` chạy hoàn toàn sau ranh giới tiến trình của 3C-0."""

    name = "local_model"

    def __init__(self, config: ModelConfig | None = None, *,
                 supervisor: WorkerSupervisor | None = None) -> None:
        self.config = config or from_environment() or ModelConfig()
        self.model = f"{self.config.runtime}:{self.config.target_locale}"
        self.supervisor = supervisor or WorkerSupervisor(
            limits=ResourceLimits(
                # `0` = CGROUP SỞ HỮU BỘ NHỚ. Đo được trên llama.cpp: VmPeak
                # ~3,2 GiB đặt chỗ trong khi cgroup chỉ bị tính ~0,9–2,0 GiB
                # thật sự chạm tới. `RLIMIT_AS` đếm phần đặt chỗ, nên mọi giá
                # trị đủ nhỏ để là một trần đều chặn model nạp — trần 896 MiB
                # cũ làm model không bao giờ chạy được.
                memory_bytes=0,
                cpu_seconds=max(2, int(self.config.timeout_s) * 4),
                processes=64, open_files=256),
            request_timeout_s=self.config.timeout_s,
            # Worker nhận cấu hình ĐÃ KIỂM, không đọc môi trường xung quanh.
            model_config_json=self.config.to_json(),
            # Điều kiện bắt buộc của 3C. Không có tham số nào ở đây nới nó ra:
            # runtime chạy TRONG worker và không cần mạng để suy luận.
            network="deny",
            # Điều kiện bắt buộc của 3C-1: worker chạy trong một scope ANH EM
            # của `shield-agent.service`, không phải con. Không dựng được scope
            # thì model bị TỪ CHỐI — xem `scope.py`.
            cgroup_scope={"memory_max": SCOPE_MEMORY_MAX,
                          "cpu_quota": SCOPE_CPU_QUOTA,
                          "tasks_max": SCOPE_TASKS_MAX},
        )

    async def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        facts, observations = self._split(request)
        worker_request = protocol.WorkerRequest(
            request_id=self._request_id(request),
            facts=facts,
            observations=observations,
            # ĐẦU VÀO CÓ CẤU TRÚC, không suy đoán từ dữ liệu. Đây là chỗ đóng
            # giới hạn locale mà Phase 3A ghi lại.
            target_locale=self.config.target_locale,
            deadline_s=self.config.timeout_s,
        )
        try:
            response = await self.supervisor.request(worker_request)
        except WorkerFailure as exc:
            # Ném tiếp, KHÔNG nuốt: Coordinator ghi `provider_error`, rồi
            # orchestrator chạy phương án dự phòng tất định. Mã hỏng được giữ
            # nguyên trong `WorkerFailure.code` để sức khoẻ đếm được.
            logger.warning("Worker model lỗi: %s", exc.code)
            raise

        if not response.ok:
            raise WorkerFailure(response.failure_code, "worker từ chối")

        try:
            # `parse` NGHIÊM NGẶT: trường lạ bị từ chối, ref sai định dạng bị
            # từ chối, action ngoài allowlist bị từ chối. Không có đường "sửa
            # nhẹ cho qua" — output nửa hợp lệ được nhận một nửa nghĩa là phần
            # bị bỏ qua chính là phần bất thường nhất.
            result = InvestigationResult.parse(
                response.result, provider=self.name, model=self.model)
        except SchemaViolation:
            # Coordinator dịch cái này thành `malformed_model_output`, rồi
            # phương án dự phòng chạy. Người dùng không bao giờ thấy output thô.
            raise
        # `investigation_id` do SHIELD đặt, không do model đặt: để model tự chọn
        # nghĩa là để nó gán kết luận cho một lượt điều tra khác.
        import dataclasses

        return dataclasses.replace(
            result,
            investigation_id=request.investigation_id,
            incident_id=request.incident_id,
        )

    @staticmethod
    def _request_id(request: InvestigationRequest) -> str:
        """`request_id` phải khớp `_REQUEST_ID` của khung: chữ, số, `_:-`."""
        raw = str(request.investigation_id or request.incident_id or "inv")
        cleaned = "".join(c for c in raw if c.isalnum() or c in "_:-")[:64]
        return cleaned or "inv"

    @staticmethod
    def _split(request: InvestigationRequest):
        """`facts` -> (dữ kiện gốc, quan sát). Cùng một nguồn, hai khối."""
        facts, observations = [], []
        for fact in request.facts:
            (observations if fact.get("kind") == _OBSERVATION_KIND else facts).append(dict(fact))
        return tuple(facts), tuple(observations)
