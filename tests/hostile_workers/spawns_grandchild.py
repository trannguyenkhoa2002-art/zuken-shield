"""13 (thêm). Sinh cháu rồi treo. Giết mỗi con để lại một cây mồ côi."""
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time\nwhile True: time.sleep(3600)"])
sys.stderr.write(f"GRANDCHILD_PID={child.pid}\n")
sys.stderr.flush()
while True:
    time.sleep(3600)
