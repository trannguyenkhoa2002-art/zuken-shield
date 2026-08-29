"""9. Tiền tố độ dài đúng, thân JSON rác."""
import struct, sys
sys.stdin.buffer.read(4)
body = b"{ khong phai json ]]]"
sys.stdout.buffer.write(struct.pack("!I", len(body)) + body)
sys.stdout.buffer.flush()
