"""7. Phun stdout vô tận. Đây là bài `communicate()` và `readline()` cùng thua."""
import sys
chunk = b"A" * 65536
while True:
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
