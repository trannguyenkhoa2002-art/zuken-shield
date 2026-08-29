#!/bin/bash
# Run after installing Shield in a disposable systemd VM.
set -euo pipefail

if [[ "${SHIELD_RUN_VM_TESTS:-}" != "1" ]]; then
    echo "Refusing: set SHIELD_RUN_VM_TESTS=1 in a disposable VM." >&2
    exit 2
fi

# Chỉ thẳng vào DB agent đang dùng. Không đặt thì store.py tự đoán qua
# os.access(W_OK): người chạy smoke test không có gid `shield` trong phiên hiện
# tại sẽ ÂM THẦM mở 1 DB rỗng ở ~/.local/share/shield/ — verify_forensic_ledger()
# trên DB rỗng luôn PASS, tức smoke test báo xanh mà không kiểm gì cả.
# (Cùng cái bẫy mà packaging/assets/shield-launcher đã phải xử lý.)
export SHIELD_DB=/var/lib/shield/shield.db

systemctl is-active --quiet shield-agent
systemctl show shield-agent -p NoNewPrivileges -p PrivateTmp -p ProtectSystem
journalctl -u shield-agent --since '-2 minutes' --no-pager | grep -q 'Shield agent khởi động'

shield-benchmark --iterations 10
# python3 hệ thống KHÔNG import được shield: gói cài code vào virtualenv riêng
# /opt/shield/.venv (postinst dựng bằng --no-index). Phải gọi đúng python đó.
/opt/shield/.venv/bin/python3 - <<'PY'
from shield.agent.store import Store
s = Store()
ok, bad, message = s.verify_forensic_ledger()
assert ok, (bad, message)
s.close()
print("PASS: forensic ledger")
PY

# Guardian (mục B2): timer phải được bật, và chạy một lượt phải ra kết quả.
# Không kiểm ở đây thì một gói quên guardian vẫn PASS toàn bộ smoke test, và
# lỗ hổng "agent bị dừng mà không ai biết" quay lại nguyên vẹn.
systemctl is-enabled --quiet shield-guardian.timer
/opt/shield/.venv/bin/shield-guardian --json > /tmp/shield-guardian-smoke.json
/opt/shield/.venv/bin/python3 - <<'GUARD'
import json
result = json.load(open("/tmp/shield-guardian-smoke.json"))
# Agent đang chạy trong smoke test, nên KHÔNG được có phát hiện nào về việc
# agent dừng hay database mất. Nếu có, guardian đang báo động giả.
bad = [f for f in result["findings"] if f["rule_id"] in {
    "GUARDIAN_AGENT_STOPPED", "GUARDIAN_DATABASE_MISSING",
    "GUARDIAN_DATABASE_CORRUPT", "GUARDIAN_LEDGER_TRUNCATED",
}]
assert not bad, bad
print("PASS: guardian")
GUARD

# Công tắc giám sát (switch.py) phải có trong bản ĐÃ CÀI — nếu thiếu, người
# dùng không tắt được Shield từ trong app khi đang ở mạng nhạy cảm.
/opt/shield/.venv/bin/python3 -c "
from shield.agent.switch import MonitoringSwitch
s = MonitoringSwitch(); s.pause('active_scan')
assert not s.allows('active_scan') and s.allows('passive')
print('PASS: monitoring switch')
"

# shield-ui không có trên PATH — entry point cho user là `shield` (launcher
# gọi sg/pkexec, không hợp cho smoke test headless). Gọi thẳng trong venv.
QT_QPA_PLATFORM=offscreen timeout 5s /opt/shield/.venv/bin/shield-ui || status=$?
if [[ "${status:-0}" != "0" && "${status:-0}" != "124" ]]; then
    exit "$status"
fi
echo "PASS: VM smoke checks"
