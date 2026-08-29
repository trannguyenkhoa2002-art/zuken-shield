"""8. Phun stderr vô tận. Không đọc thì worker chặn ở write và trông như treo."""
import sys
chunk = "E" * 65536
while True:
    sys.stderr.write(chunk)
    sys.stderr.flush()
