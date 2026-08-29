"""11. Gửi nửa khung rồi đóng ống THẬT.

`sys.stdout.buffer.close()` KHÔNG đóng fd 1 trên CPython — đã kiểm, fd vẫn mở
và agent không bao giờ nhận EOF, nên bài test hoá ra đo timeout chứ không đo
đường ống-đóng-giữa-chừng. `os.close(1)` mới là thứ tạo ra EOF thật.
"""
import os, struct, sys, time
sys.stdin.buffer.read(4)
sys.stdout.buffer.write(struct.pack("!I", 4096) + b"{\"schema_ver")
sys.stdout.buffer.flush()
os.close(1)
time.sleep(30)
