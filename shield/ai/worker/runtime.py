"""Nạp và chạy model cục bộ — BÊN TRONG worker đã bị cách ly.

Đây là lý do chọn runtime chạy trong tiến trình thay vì một daemon: suy luận
xảy ra ở ĐÂY, nên nó nằm trọn trong `RLIMIT_AS`, `RLIMIT_CPU` và network
namespace rỗng mà 3C-0 dựng. Với một daemon (Ollama), suy luận chạy trong tiến
trình của daemon — ngoài mọi trần của ta — và worker chỉ còn là một HTTP client
mỏng. Khi đó "worker RSS đỉnh" không đo model, và cả Phase 3C-0 không bảo vệ
đúng thứ nó được dựng để bảo vệ.

Registry ĐÓNG. Không plugin, không `importlib` theo tên từ cấu hình: nạp một
module theo chuỗi người dùng đặt là thực thi mã tuỳ ý bằng quyền của worker.
"""

from __future__ import annotations

import json

from shield.ai.model_config import ModelConfig


class RuntimeUnavailable(RuntimeError):
    """Runtime hoặc model không có mặt. Đây là lý do TỪ CHỐI, không phải lỗi.

    Phân biệt hai thứ là quan trọng: "chưa cài" dẫn tới một dòng hướng dẫn cài,
    còn "hỏng" dẫn tới một cuộc điều tra. Gộp chúng lại thì người vận hành đọc
    sai nguyên nhân ngay ở bước đầu.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code


class LlamaCppRuntime:
    """`llama.cpp` qua `llama-cpp-python`, nạp trong tiến trình worker."""

    name = "llama_cpp"

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        self._llama = None

    def load(self) -> None:
        model_path = self.config.validate_model()
        try:
            # Nạp MUỘN, và chỉ sau khi trần + netns + hạ quyền đã xong. Một
            # thư viện native nạp sớm là một thư viện native chạy với trần chưa
            # hạ — và nó là thứ duy nhất ở đây có thể segfault.
            from llama_cpp import Llama
        except ImportError as exc:
            raise RuntimeUnavailable(
                "runtime_unavailable",
                "chưa cài llama-cpp-python trong môi trường của agent") from exc
        self._llama = Llama(
            model_path=str(model_path),
            n_ctx=self.config.context_tokens,
            n_threads=self.config.threads,
            seed=self.config.seed,
            # Không tải gì từ mạng, không log ra stdout — stdout là kênh KHUNG,
            # và một dòng log lọt vào đó làm hỏng khung.
            verbose=False,
        )

    def compile_grammar(self, gbnf: str):
        """GBNF -> đối tượng ngữ pháp của llama.cpp, hoặc `None` nếu không có.

        Ngữ pháp ràng buộc ở TẦNG LẤY MẪU: token nào phá cú pháp thì xác suất
        bị đặt về 0, nên model KHÔNG THỂ sinh ra JSON hỏng hay một mã ngoài
        registry. Đây mạnh hơn hẳn kiểm-sau-khi-sinh — và nó là câu trả lời
        đúng cho một model nhỏ hay bọc JSON trong ```json rồi nói thêm vài câu.

        Cách sai là nới lỏng bộ phân tích để "cứu" JSON khỏi văn xuôi. Ràng
        buộc lúc sinh là tất định; gỡ rào lúc đọc là đoán.
        """
        if not gbnf:
            return None
        try:
            from llama_cpp import LlamaGrammar
        except ImportError:
            return None
        try:
            return LlamaGrammar.from_string(gbnf, verbose=False)
        except Exception as exc:  # noqa: BLE001 — ngữ pháp sai là lỗi của ta
            raise RuntimeUnavailable("runtime_unavailable",
                                     f"ngữ pháp không hợp lệ: {type(exc).__name__}") from exc

    def generate(self, prompt: str, *, gbnf: str = "") -> str:
        if self._llama is None:
            raise RuntimeUnavailable("runtime_unavailable", "model chưa được nạp")
        grammar = self.compile_grammar(gbnf)
        out = self._llama.create_completion(
            prompt=prompt,
            max_tokens=self.config.max_output_tokens,
            temperature=self.config.temperature,
            # Phạt lặp. Model 1,5B đã quan sát được là lặp nguyên một mệnh đề
            # cho tới khi hết token. Đây KHÔNG phải thêm ngẫu nhiên: nhiệt độ
            # vẫn 0, nên cùng một prompt vẫn cho cùng một câu trả lời.
            repeat_penalty=self.config.repeat_penalty,
            # Dừng ở đúng chỗ JSON kết thúc. Không cắt gọt về sau bằng regex:
            # "khôi phục" JSON từ văn xuôi là đoán, và đoán ở tầng này nghĩa là
            # một model bịa được xử lý như một model đúng.
            stop=["\n\n\n"],
            **({"grammar": grammar} if grammar is not None else {}),
        )
        text = out["choices"][0]["text"]
        if len(text.encode("utf-8")) > self.config.max_output_bytes:
            raise RuntimeUnavailable("oversized_response", "model sinh quá trần byte")
        return text


# Registry ĐÓNG — tên là dữ liệu, lớp là mã, và chỉ mã nguồn quyết định ánh xạ.
RUNTIMES = {LlamaCppRuntime.name: LlamaCppRuntime}


def load_runtime(config: ModelConfig):
    factory = RUNTIMES.get(config.runtime)
    if factory is None:
        raise RuntimeUnavailable("runtime_unavailable",
                                 f"runtime không được hỗ trợ: {config.runtime!r}")
    runtime = factory(config)
    runtime.load()
    return runtime


def parse_model_output(text: str, *, request_id: str) -> dict:
    """Văn bản model -> dict, NGHIÊM NGẶT. Không đoán, không cứu vãn.

    Không regex trích JSON từ văn xuôi, không cắt phần thừa, không sửa dấu
    phẩy. Mỗi thủ thuật "khôi phục" là một lần biến một output sai thành một
    output trông đúng, và phần bị sửa luôn là phần bất thường nhất.

    `parse_constant` chặn `NaN`/`Infinity`: JSON chuẩn không có chúng, nhưng
    `json.loads` của Python nhận — và một `Infinity` lọt vào một trường số sẽ
    đi rất xa trước khi có ai nhận ra.
    """
    stripped = (text or "").strip()
    if not stripped:
        raise ValueError("model không trả về gì")

    def _no_constants(name):
        raise ValueError(f"JSON chứa hằng không hợp lệ: {name}")

    decoder = json.JSONDecoder(parse_constant=_no_constants)
    payload, end = decoder.raw_decode(stripped)
    if stripped[end:].strip():
        # Rác phía sau nghĩa là model nói thêm sau khi đã đóng JSON. Có thể vô
        # hại, có thể là một khối JSON thứ hai. Không phân biệt được thì không
        # nhận.
        raise ValueError("có dữ liệu thừa sau khối JSON")
    if not isinstance(payload, dict):
        raise ValueError("output phải là một object JSON")

    # Hai trường định danh do SHIELD đặt, không do model đặt. Model tự chọn
    # `investigation_id` nghĩa là nó gán kết luận cho một lượt điều tra khác.
    payload["investigation_id"] = request_id
    payload["incident_id"] = payload.get("incident_id", request_id)
    return payload


def json_object_grammar() -> str:
    """GBNF: đầu ra PHẢI là đúng một object JSON, không rào ```, không lời bạt.

    Chỉ ràng buộc HÌNH DẠNG, không ràng buộc nội dung — nội dung đã có
    `contracts.py` kiểm nghiêm ngặt hơn nhiều. Đây là để chặn đúng kiểu hỏng đã
    đo được trên model 1,5B: JSON đúng, nhưng gói trong ```json và kèm theo vài
    câu tự sự phía sau, khiến bộ phân tích nghiêm ngặt từ chối cả lượt.
    """
    return r"""
root   ::= object
object ::= "{" ws (string ws ":" ws value (ws "," ws string ws ":" ws value)*)? ws "}"
array  ::= "[" ws (value (ws "," ws value)*)? ws "]"
value  ::= object | array | string | number | "true" | "false" | "null"
string ::= "\"" ([^"\\] | "\\" ["\\/bfnrt])* "\""
number ::= "-"? ("0" | [1-9][0-9]*) ("." [0-9]+)? ([eE] [-+]? [0-9]+)?
ws     ::= [ \t\n]*
"""


# Trần ký tự cho MỖI ô của câu trả lời hỏi đáp, ép ở tầng ngữ pháp.
# Hợp đồng là hai tới bốn câu; 400 ký tự tiếng Việt vừa đủ và bảo đảm cả object
# JSON đóng lại trong ngân sách token đầu ra.
CHAT_FIELD_CHARS = 400


def chat_grammar(max_chars: int = CHAT_FIELD_CHARS) -> str:
    """GBNF cho một câu trả lời hỏi đáp. ĐÚNG hai khoá chuỗi, CÓ TRẦN ĐỘ DÀI.

    `tool_requests` không nằm trong ngữ pháp này, và đó là điểm chính: giải mã
    bị RÀNG BUỘC theo ngữ pháp, nên một yêu cầu công cụ không phải là thứ bị từ
    chối sau khi sinh ra — nó không sinh ra được. Cũng không có `evidence_refs`
    hay `severity`: ref do backend gắn từ dữ liệu đã kiểm, còn mức nghiêm trọng
    là của Shield. Model không có ô nào để ghi đè chúng.

    Trần `{0,N}` trên mỗi chuỗi KHÔNG phải để cho gọn. Không có nó, model viết
    một câu trả lời dài, chạm trần token giữa chừng, và JSON không bao giờ được
    đóng — `parse_model_output` từ chối (đúng), worker báo `crashed`, và người
    dùng chờ 80 giây để không nhận được gì. Đo được đúng như vậy. Ràng buộc độ
    dài ở tầng lấy mẫu là cách duy nhất bảo đảm object luôn đóng trong ngân
    sách token.
    """
    limit = max(1, int(max_chars))
    return (
        r'root ::= "{" ws "\"answer\"" ws ":" ws short ws "," ws '
        r'"\"limitations\"" ws ":" ws short ws "}"' "\n"
        r'short ::= "\"" char{0,%d} "\""' % limit + "\n"
        r'char ::= [^"\\] | "\\" ["\\/bfnrt]' "\n"
        r'ws ::= [ \t\n]*' "\n"
    )


def explanation_grammar() -> str:
    """GBNF cho ba ô văn xuôi. Ràng buộc HÌNH DẠNG, không ràng buộc nội dung.

    Ba khoá, đúng thứ tự, đúng kiểu chuỗi — nên `schema_validity` là tính chất
    của ngữ pháp chứ không phải may mắn. Nội dung vẫn do `OutputValidator` và
    bộ chấm claim phán xử: ngữ pháp không biết một câu có căn cứ hay không, và
    coi nó như kiểm ngữ nghĩa là hiểu sai nó làm gì.
    """
    # MỘT DÒNG cho `root`. GBNF của llama.cpp không nối dòng cho một luật —
    # bản đầu viết `root` trên ba dòng và trình phân tích báo "expecting ::=".
    # Dùng raw string: dấu nháy bên trong terminal phải là `\"` NGUYÊN VĂN, và
    # bản escape thường biến nó thành `""` — ngữ pháp vẫn biên dịch nhưng sinh
    # ra JSON sai, tức là hỏng theo kiểu im lặng.
    return (
        r'root ::= "{" ws "\"analysis\"" ws ":" ws str ws "," ws '
        r'"\"hypothesis_rationale\"" ws ":" ws str ws "," ws '
        r'"\"why_this_matters\"" ws ":" ws str ws "}"' "\n"
        r'str ::= "\"" ([^"\\] | "\\" ["\\/bfnrt])* "\""' "\n"
        r'ws ::= [ \t\n]*' "\n"
    )
