"""4. Cấp phát tới khi chạm trần. Phải là RLIMIT chặn, không phải OOM killer
của cả máy — nếu kernel phải chọn nạn nhân thì nạn nhân có thể là agent."""
import os, sys
from shield.ai.worker import limits as L
L.apply(L.ResourceLimits.from_json(os.environ.get("SHIELD_WORKER_LIMITS", "{}")))
blocks = []
try:
    while True:
        blocks.append(bytearray(16 * 1024 * 1024))
except MemoryError:
    sys.stderr.write("MEMORY_LIMIT_REACHED\n")
    raise SystemExit(9)
