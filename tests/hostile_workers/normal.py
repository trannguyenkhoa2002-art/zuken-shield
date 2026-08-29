"""1. Trả lời đúng lược đồ. Đường thẳng — nếu bài này hỏng thì mọi bài sau vô nghĩa."""
import json, struct, sys
size, = struct.unpack("!I", sys.stdin.buffer.read(4))
req = json.loads(sys.stdin.buffer.read(size))
body = json.dumps({"schema_version": 1, "kind": "response",
                   "request_id": req["request_id"], "ok": True,
                   "failure_code": "ok", "result": {"summary": "ổn"}}).encode()
sys.stdout.buffer.write(struct.pack("!I", len(body)) + body)
sys.stdout.buffer.flush()
