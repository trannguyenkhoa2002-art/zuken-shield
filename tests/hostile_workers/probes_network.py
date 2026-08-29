"""Worker thử MỞ MẠNG. Dùng để chứng minh default-deny, không phải để đóng gói."""
import json, socket, struct, sys
size, = struct.unpack("!I", sys.stdin.buffer.read(4))
req = json.loads(sys.stdin.buffer.read(size))
out = {}
for label, (host, port) in {"public": ("1.1.1.1", 53), "lan": ("192.168.1.1", 80),
                            "loopback": ("127.0.0.1", 11434)}.items():
    try:
        s = socket.socket(); s.settimeout(2); s.connect((host, port))
        out[label] = "ALLOWED"; s.close()
    except Exception as exc:
        out[label] = f"denied:{type(exc).__name__}"
try:
    socket.getaddrinfo("example.com", 80); out["dns"] = "ALLOWED"
except Exception as exc:
    out["dns"] = f"denied:{type(exc).__name__}"
body = json.dumps({"schema_version": 1, "kind": "response",
                   "request_id": req["request_id"], "ok": True,
                   "failure_code": "ok", "result": out}).encode()
sys.stdout.buffer.write(struct.pack("!I", len(body)) + body)
sys.stdout.buffer.flush()
