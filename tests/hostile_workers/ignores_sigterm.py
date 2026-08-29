"""12. Phớt lờ SIGTERM. Chỉ SIGKILL trên cả nhóm mới dứt điểm."""
import signal, time
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, signal.SIG_IGN)
while True:
    time.sleep(3600)
