"""Worker model theo KỊCH BẢN — chỉ dùng cho test và corpus đánh giá.

Không đóng gói cùng sản phẩm. Nó thay đúng MỘT thứ trong đường ống — output
của model — và để nguyên mọi thứ khác chạy thật: khung truyền, trần tài nguyên,
netns, Coordinator, validator, renderer.

Kịch bản đến qua argv (một đường dẫn file JSON), không qua môi trường: môi
trường worker cố ý chỉ có 5 biến, và nới nó ra cho tiện test là nới đúng cái
ranh giới đang được đo.

Mỗi yêu cầu là một TIẾN TRÌNH MỚI, nên "lượt thứ mấy" được đếm bằng một file
trạng thái cạnh kịch bản.
"""
import json, os, struct, sys, time
from pathlib import Path

script = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
state = Path(sys.argv[1] + ".round")
turn = int(state.read_text()) if state.exists() else 0
try:
    state.write_text(str(turn + 1))
except OSError:
    pass

if script.get("hang"):
    time.sleep(300)
if script.get("crash"):
    os.abort()

size, = struct.unpack("!I", sys.stdin.buffer.read(4))
request = json.loads(sys.stdin.buffer.read(size))

responses = script.get("responses") or [{}]
payload = responses[min(turn, len(responses) - 1)]

if script.get("raw_output"):
    # Model trả về văn xuôi thay vì JSON. Vỏ worker thật sẽ ném ở
    # `parse_model_output`; ở đây ta mô phỏng đúng mã lỗi nó sinh ra.
    body = json.dumps({"schema_version": 1, "kind": "response",
                       "request_id": request["request_id"], "ok": False,
                       "failure_code": "crashed", "result": {}}).encode()
else:
    result = dict(payload)
    result.setdefault("investigation_id", request["request_id"])
    result.setdefault("incident_id", request["request_id"])
    # Kịch bản có thể yêu cầu ghi lại locale đã nhận, để test chứng minh
    # `target_locale` thật sự đi qua ranh giới chứ không bị suy đoán.
    if script.get("echo_locale"):
        result["summary"] = f"locale={request['target_locale']}"
    body = json.dumps({"schema_version": 1, "kind": "response",
                       "request_id": request["request_id"], "ok": True,
                       "failure_code": "ok", "result": result}).encode()

sys.stdout.buffer.write(struct.pack("!I", len(body)) + body)
sys.stdout.buffer.flush()
