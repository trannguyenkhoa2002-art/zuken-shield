"""Cấu hình model cục bộ — ĐÓNG và có trần (mục 6 của Phase 3C).

Mọi trường ở đây là một trần. Không có trường nào nhận "không giới hạn", và
không có trường nào đọc từ một nơi kẻ tấn công ghi được mà không qua kiểm.

Ba luật:

1. **Không tự tải model.** Không HTTP, không `hf_hub_download`, không mirror.
   Cài model là việc của quản trị viên, một lần, có ý thức — và một adapter tự
   tải về là một adapter tự mở kết nối ra Internet, đúng thứ §3 vừa cắt.
2. **Model lạ -> tắt.** Không đoán, không thử. Cấu hình sai phải khiến Shield
   chạy KHÔNG có AI, chứ không phải khiến Shield chạy với một file lạ.
3. **Nhiệt độ thấp, mặc định gần tất định.** Một model điều tra an ninh không
   được sáng tạo. `temperature=0.0` và seed cố định là mặc định; ai muốn khác
   phải gõ tay.

Tier được hỗ trợ ở 3C: **model nhỏ (0,5B–1,5B)**. Trần `max_model_bytes` thi
hành điều đó bằng máy — một GGUF 7B không lọt qua, nên "chỉ hỗ trợ model nhỏ"
là một ràng buộc chứ không phải một câu trong tài liệu.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

# Runtime được hỗ trợ. Danh sách ĐÓNG — tên lạ là lỗi cấu hình, không phải một
# gợi ý để thử.
SUPPORTED_RUNTIMES = frozenset({"llama_cpp"})

# Chế độ AI. Đóng, và hiện chỉ có MỘT — `explanation_only`.
#
# Đây là hợp đồng, không phải một tuỳ chọn: ở chế độ này model chỉ được viết ba
# ô văn xuôi và KHÔNG phát ToolRequest được. Đo trên model thật cho
# intent_accuracy 61,9% so với cổng 95%, nên để nó lái vòng lặp tool là mua một
# rủi ro không đổi lấy gì.
#
# Và nó phải BẤT KHẢ THI chứ không phải "ta sẽ không hỏi": ngữ pháp giải thích
# chỉ có ba khoá nên model không sinh ra `tool_requests` được, và adapter vẫn
# vứt + đếm nếu bằng cách nào đó nó xuất hiện. Một lời hứa không phải một hàng
# rào.
# `chat`: hỏi đáp gắn vào MỘT sự cố. Vẫn là văn xuôi và chỉ văn xuôi —
# không phân loại, không công cụ, không hành động. Xem `chat_grammar`.
AI_MODES = frozenset({"explanation_only", "chat"})

# Thư mục model được phép. Cùng lý do như `TRUSTED_PREFIXES`: một file model là
# đầu vào cho mã native, và mã native đọc file lạ là mã native bị khai thác.
MODEL_PREFIXES = ("/opt/shield/models", "/usr/lib/shield/models",
                  "/var/lib/shield/models")

# Trần tier nhỏ. Một GGUF 1,5B lượng tử hoá q4 khoảng 0,9–1,1 GB; 2 GiB cho
# thoải mái mà vẫn loại hẳn 7B (~4,7 GB).
MAX_MODEL_BYTES = 2 * 1024 * 1024 * 1024

ENV_RUNTIME = "SHIELD_AI_MODEL_RUNTIME"
ENV_MODEL_PATH = "SHIELD_AI_MODEL_PATH"
ENV_CONFIG = "SHIELD_AI_MODEL_CONFIG"

# Locale ĐÓNG. Trùng đúng hai ngôn ngữ giao diện đã có; thêm một cái thứ ba là
# thêm một bảng dịch, không phải thêm một chuỗi.
SUPPORTED_LOCALES = ("vi", "en")


class ModelConfigError(ValueError):
    """Cấu hình không hợp lệ. Fail closed — chạy KHÔNG có AI."""


@dataclasses.dataclass(frozen=True)
class ModelConfig:
    runtime: str = "llama_cpp"
    mode: str = "explanation_only"
    model_path: str = ""
    context_tokens: int = 4096
    max_output_tokens: int = 768
    temperature: float = 0.0
    # 1.0 = TẮT. Xem `runtime.generate`: đây là phạt lặp, không phải ngẫu nhiên
    # hoá — nhiệt độ vẫn 0 để cùng đầu vào cho cùng đầu ra.
    repeat_penalty: float = 1.0
    seed: int = 1
    threads: int = 2
    timeout_s: float = 60.0
    max_output_bytes: int = 256 * 1024
    target_locale: str = "vi"

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), sort_keys=True)

    @classmethod
    def parse(cls, raw: dict) -> "ModelConfig":
        """Kẹp mọi số về khoảng hợp lệ, TỪ CHỐI mọi trường lạ.

        Kẹp chứ không từ chối với số: một `max_output_tokens` quá lớn là cấu
        hình vụng, không phải tấn công, và tắt cả AI vì nó thì quá tay. Nhưng
        một TRƯỜNG lạ thì bị từ chối — nó nghĩa là có ai đó tưởng mình đang bật
        một thứ, và thứ đó im lặng không có tác dụng.
        """
        known = {f.name for f in dataclasses.fields(cls)}
        unknown = set(raw) - known
        if unknown:
            raise ModelConfigError(f"cấu hình có trường lạ: {sorted(unknown)}")

        runtime = str(raw.get("runtime", "llama_cpp"))
        if runtime not in SUPPORTED_RUNTIMES:
            raise ModelConfigError(f"runtime không được hỗ trợ: {runtime!r}")

        mode = str(raw.get("mode", "explanation_only"))
        if mode not in AI_MODES:
            raise ModelConfigError(f"chế độ AI không được hỗ trợ: {mode!r}")

        locale = str(raw.get("target_locale", "vi"))
        if locale not in SUPPORTED_LOCALES:
            raise ModelConfigError(f"target_locale không được hỗ trợ: {locale!r}")

        def clamp(name, low, high, default, cast=int):
            try:
                return max(low, min(cast(raw.get(name, default)), high))
            except (TypeError, ValueError) as exc:
                raise ModelConfigError(f"{name} không phải số") from exc

        return cls(
            runtime=runtime,
            mode=mode,
            model_path=str(raw.get("model_path", "")),
            context_tokens=clamp("context_tokens", 512, 32768, 4096),
            max_output_tokens=clamp("max_output_tokens", 64, 4096, 768),
            # Trần 1.0, không phải 2.0: trên 1.0 là vùng model bắt đầu bịa, và
            # một model điều tra an ninh không được sáng tạo.
            temperature=clamp("temperature", 0.0, 1.0, 0.0, float),

            repeat_penalty=clamp("repeat_penalty", 1.0, 1.5, 1.0),
            seed=clamp("seed", 0, 2**31 - 1, 1),
            threads=clamp("threads", 1, 8, 2),
            timeout_s=clamp("timeout_s", 1.0, 300.0, 60.0, float),
            max_output_bytes=clamp("max_output_bytes", 4096, 1024 * 1024, 256 * 1024),
            target_locale=locale,
        )

    def validate_model(self, *, prefixes: tuple[str, ...] = MODEL_PREFIXES,
                       max_bytes: int = MAX_MODEL_BYTES) -> Path:
        """-> đường dẫn model đã kiểm, hoặc `ModelConfigError`."""
        if not self.model_path:
            raise ModelConfigError("chưa cấu hình model_path")
        raw = Path(self.model_path)
        if not raw.is_absolute():
            raise ModelConfigError(f"model_path phải tuyệt đối: {raw}")
        try:
            resolved = raw.resolve(strict=True)
        except OSError as exc:
            raise ModelConfigError(f"không tìm thấy model: {raw}") from exc
        if not any(resolved.is_relative_to(p) for p in prefixes):
            raise ModelConfigError(f"{resolved} nằm ngoài thư mục model được phép")
        if not resolved.is_file():
            raise ModelConfigError(f"{resolved} không phải file")
        size = resolved.stat().st_size
        if size > max_bytes:
            # Tier được hỗ trợ ở 3C là model NHỎ. Trần này là thứ thi hành điều
            # đó bằng máy thay vì bằng một câu trong tài liệu.
            raise ModelConfigError(
                f"model {size} byte vượt trần tier nhỏ {max_bytes} byte")
        if size == 0:
            raise ModelConfigError("file model rỗng")
        return resolved


def from_environment(env: dict | None = None) -> ModelConfig | None:
    """Đọc cấu hình từ môi trường. `None` nghĩa là KHÔNG bật model cục bộ.

    `None` chứ không phải một cấu hình mặc định: mặc định production là
    `disabled`, và một hàm trả về cấu hình "hợp lệ" khi chưa ai cấu hình gì sẽ
    làm chỗ gọi tưởng model đã sẵn sàng.
    """
    env = os.environ if env is None else env
    blob = env.get(ENV_CONFIG, "").strip()
    if blob:
        try:
            raw = json.loads(blob)
        except json.JSONDecodeError as exc:
            raise ModelConfigError(f"{ENV_CONFIG} không phải JSON hợp lệ") from exc
        if not isinstance(raw, dict):
            raise ModelConfigError(f"{ENV_CONFIG} phải là một object JSON")
    else:
        raw = {}
    if env.get(ENV_RUNTIME):
        raw.setdefault("runtime", env[ENV_RUNTIME])
    if env.get(ENV_MODEL_PATH):
        raw.setdefault("model_path", env[ENV_MODEL_PATH])
    if not raw.get("model_path"):
        return None
    return ModelConfig.parse(raw)
