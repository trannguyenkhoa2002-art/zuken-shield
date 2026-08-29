#!/bin/bash
# Hai phép thử cuối của kế hoạch 1.1 — bắt buộc chạy bằng root trên máy thật.
#
#   sudo SHIELD_RUN_ROOT_TESTS=1 ./scripts/final-validation.sh
#
# Script CÓ dừng agent thật trong khoảng 60-90 giây (phép thử 5 đòi đúng điều
# đó) rồi bật lại. Cách ly mạng chạy trong network namespace riêng, không đụng
# tới nftables của máy.
set -euo pipefail

if [[ "${SHIELD_RUN_ROOT_TESTS:-}" != "1" ]]; then
    echo "Từ chối chạy: cần SHIELD_RUN_ROOT_TESTS=1." >&2
    echo "Script này sẽ DỪNG shield-agent khoảng 60-90 giây." >&2
    exit 2
fi
[[ "$(id -u)" == "0" ]] || { echo "Cần chạy bằng root." >&2; exit 2; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Ưu tiên mã trong repo, KHÔNG phải /opt/shield: bản đang cài có thể còn cũ hơn
# thứ ta muốn kiểm. Chọn nhầm ở đây thì mọi phép thử đều chạy trên mã cũ và
# báo FAIL cho những lỗi đã sửa từ lâu.
PY="${SHIELD_PYTHON:-$ROOT_DIR/.venv/bin/python}"
[[ -x "$PY" ]] || PY=/opt/shield/.venv/bin/python3
[[ -x "$PY" ]] || { echo "Không tìm thấy trình thông dịch Python của Shield." >&2; exit 2; }
# venv của repo không cài `shield` như một gói — nó chỉ import được khi thư mục
# dự án nằm trong đường dẫn.
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
export SHIELD_DB=/var/lib/shield/shield.db

# Kiểm tra trước khi đụng vào bất cứ thứ gì. Dừng agent thật rồi mới phát hiện
# thiếu module là vừa vô ích vừa để máy mất giám sát không lý do — và một FAIL
# do script tự cấu hình sai sẽ bị đọc nhầm thành lỗi sản phẩm.
if ! "$PY" - <<'PREFLIGHT'
import shield.guardian.__main__  # noqa: F401
from shield.security.response import DeadManSwitch  # noqa: F401
PREFLIGHT
then
    echo >&2
    echo "DỪNG: $PY không import được mã 1.1 (shield.guardian / DeadManSwitch)." >&2
    echo "Chưa có gì bị thay đổi, agent vẫn đang chạy." >&2
    echo "Chạy lại với: sudo SHIELD_RUN_ROOT_TESTS=1 SHIELD_PYTHON=$ROOT_DIR/.venv/bin/python $0" >&2
    exit 2
fi
echo "Dùng trình thông dịch: $PY"
"$PY" -c "import shield, pathlib; print('mã Shield tại:', pathlib.Path(shield.__file__).parent)"
echo
FAIL=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; FAIL=1; }

# Bật lại agent dù script hỏng giữa chừng. Để máy mất giám sát vì một phép
# thử bỏ dở là cái giá không được phép trả.
restore() {
    systemctl is-active --quiet shield-agent || systemctl start shield-agent || true
    ip netns list 2>/dev/null | grep -q '^shieldtest' && ip netns delete shieldtest || true
}
trap restore EXIT

echo "=== Phép thử 5: Guardian có phát hiện agent bị dừng không ==="
WAS_ACTIVE=0
systemctl is-active --quiet shield-agent && WAS_ACTIVE=1

# Xoá state để lần chạy này so với trạng thái mới, không phải ảnh chụp cũ.
rm -f /var/lib/shield/guardian-state.json
"$PY" -m shield.guardian >/dev/null 2>&1 || true   # lượt chụp ảnh nền

systemctl stop shield-agent
sleep 3
OUT="$("$PY" -m shield.guardian 2>&1 || true)"
if grep -q "GUARDIAN_AGENT_STOPPED" <<<"$OUT"; then
    pass "Guardian báo agent bị dừng"
else
    fail "Guardian KHÔNG báo gì khi agent dừng"; echo "$OUT" | head -20
fi
# Và phải phân biệt được "người dùng chủ động tắt" với "bị ai đó tắt".
if grep -q "GUARDIAN_AGENT_STOPPED_BY_OPERATOR" <<<"$OUT"; then
    fail "nhận nhầm thành thao tác có phép, dù không ai bấm nút tắt trong app"
fi
[[ "$WAS_ACTIVE" == "1" ]] && systemctl start shield-agent
sleep 3
systemctl is-active --quiet shield-agent && pass "agent đã chạy lại" || fail "agent KHÔNG chạy lại"

echo
echo "=== Phép thử 7: cách ly mạng + dead-man tự gỡ ==="
ip netns delete shieldtest 2>/dev/null || true
ip netns add shieldtest
ip netns exec shieldtest ip link set lo up
ip netns exec shieldtest nft list ruleset >/dev/null 2>&1 \
    || { fail "netns không dùng được nftables — bỏ qua phép thử 7"; exit $FAIL; }

"$PY" - <<'PYEOF' || FAIL=1
import subprocess, time, tempfile
from pathlib import Path
from shield.security.response import DeadManSwitch, IsolationPlan

def nft(*args):
    return subprocess.run(["ip", "netns", "exec", "shieldtest", "nft", *args],
                          capture_output=True, text=True)

state = Path(tempfile.mkdtemp()) / "deadman.json"
switch = DeadManSwitch(state)
TARGET = "10.0.0.99"

plan = IsolationPlan(TARGET, ttl_s=60)
impact = plan.impact()
assert impact, "cách ly phải nói rõ nó sẽ làm hỏng những gì"
print("  ảnh hưởng nếu cách ly:", ", ".join(item["service"] for item in impact))

# Đặt luật trong netns, đúng hình dạng luật cách ly thật.
nft("add", "table", "inet", "shield")
nft("add", "chain", "inet", "shield", "isolate",
    "{ type filter hook forward priority 0 ; }")
r = nft("add", "rule", "inet", "shield", "isolate", "ip", "saddr", TARGET, "drop")
assert r.returncode == 0, r.stderr
assert TARGET in nft("list", "ruleset").stdout, "luật không vào được"
print("  PASS: luật cách ly đã áp trong netns")

switch.arm(TARGET, 3.0)
assert TARGET in switch.armed(), "dead-man phải ở trạng thái đã lên cò"
assert switch.expired() == [], "vừa lên cò đã hết hạn là sai"
assert switch.renew(TARGET, 3.0), "gia hạn phải thành công khi đang lên cò"
time.sleep(4)
assert switch.expired() == [TARGET], "quá hạn mà không báo = cách ly kẹt vĩnh viễn"
print("  PASS: dead-man hết hạn đúng lúc")

# Trạng thái phải sống sót qua việc tiến trình chết — dead-man chỉ có nghĩa
# khi nó vẫn gỡ được cách ly sau một lần agent bị giết.
reloaded = DeadManSwitch(state)
assert reloaded.expired() == [TARGET], "khởi động lại là mất trạng thái dead-man"
print("  PASS: dead-man sống sót qua khởi động lại")

nft("flush", "table", "inet", "shield")
assert TARGET not in nft("list", "ruleset").stdout, "gỡ luật không sạch"
print("  PASS: gỡ cách ly sạch")
PYEOF

ip netns delete shieldtest 2>/dev/null || true
echo
[[ "$FAIL" == "0" ]] && echo "==> TẤT CẢ ĐỀU PASS" || echo "==> CÓ PHÉP THỬ HỎNG"
exit $FAIL
