"""Chọn model, độc lập nhà cung cấp (mục 2.1).

`disabled` là MẶC ĐỊNH production. Không có biến môi trường nào bật được một
provider từ xa mà không có người gõ tay vào cấu hình — mục 5.2: "Remote provider
mặc định tắt."

Vì sao provider là một Protocol chứ không phải một lớp cha: gói `shield.ai`
không được phép biết SDK nào tồn tại. Một adapter tiến trình riêng cài SDK của
nó và nói chuyện qua hợp đồng này; agent detection phải chạy được khi adapter
đó chết, và nó chết được mà không kéo theo ai.
"""

from __future__ import annotations

import logging
import time
from typing import Protocol, runtime_checkable

from shield.ai.contracts import InvestigationRequest, InvestigationResult

logger = logging.getLogger("shield.ai.provider")


@runtime_checkable
class AnalystModel(Protocol):
    name: str

    async def investigate(self, request: InvestigationRequest) -> InvestigationResult: ...


class DisabledProvider:
    """Mặc định production: không phân tích gì, và nói rõ là không.

    Trả về một kết quả RỖNG HỢP LỆ chứ không ném lỗi. Ném lỗi ở đây sẽ buộc mọi
    chỗ gọi phải bọc try/except, và một trong số đó sẽ quên — rồi việc tắt AI
    trở thành nguyên nhân làm hỏng một đường dẫn không liên quan.
    """

    name = "disabled"

    async def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        return InvestigationResult(
            investigation_id=request.investigation_id,
            incident_id=request.incident_id,
            summary="",
            limitations=("AI analyst đang tắt trên endpoint này.",),
            provider=self.name, model="none", analysed_ts=time.time(),
        )


def select_provider(name: str, **kwargs) -> AnalystModel:
    """Chọn provider theo tên. Tên lạ -> `disabled`, không phải lỗi.

    Fail closed nghĩa là: cấu hình sai thì Shield chạy KHÔNG có AI, chứ không
    phải Shield không chạy. Detection là thứ phải sống sót qua mọi cấu hình sai.
    """
    from shield.ai.local_provider import LocalDeterministicAnalyst

    if name == "local":
        return LocalDeterministicAnalyst(**kwargs)
    if name == "local_model":
        # Phase 3C: model cục bộ, chạy sau ranh giới tiến trình. KHÔNG phải mặc
        # định, và không có biến môi trường nào bật nó ngoài việc gõ đúng tên
        # này vào cấu hình — mục 5.2: provider phải do người đặt, không do một
        # giá trị mặc định đặt hộ.
        from shield.ai.local_model import LocalModelAnalyst

        try:
            return LocalModelAnalyst(**kwargs)
        except Exception:  # noqa: BLE001 — cấu hình sai không được chặn Shield
            # Fail closed về `disabled`, không ném: detection là thứ phải sống
            # sót qua mọi cấu hình sai.
            logger.exception("Không dựng được adapter model cục bộ — chạy KHÔNG có AI")
            return DisabledProvider()
    return DisabledProvider()
