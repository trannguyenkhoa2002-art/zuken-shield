"""10. Khai báo một khung khổng lồ. Agent phải từ chối TRƯỚC khi cấp phát."""
import struct, sys
sys.stdin.buffer.read(4)
sys.stdout.buffer.write(struct.pack("!I", 4_000_000_000))
sys.stdout.buffer.flush()
import time
time.sleep(30)
