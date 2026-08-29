"""Watchdog phải được trả lời TRƯỚC hạn, kể cả khi khởi động nguội.

Sự cố có thật, trên máy production, lặp lại nhiều lần và chỉ lúc boot:

    systemd[1]: shield-agent.service: Watchdog timeout (limit 1min 30s)!
    systemd[1]: Killing process ... with signal SIGABRT.

Cơ chế, dựng lại từ journal có mốc chính xác tới mili giây:

    `Type=simple`, nên systemd đếm `WatchdogSec` từ lúc KHỞI ĐỘNG dịch vụ,
    không phải từ `READY=1`. Vòng watchdog cũ ngủ trọn một chu kỳ trước cái
    ping đầu tiên, nên hạn thực tế là:

        thời gian khởi động + interval < WatchdogSec

    Khởi động nguội đo được: 46,0 giây. Chu kỳ: 45 giây. Tổng 91 giây, hạn 90
    giây — trễ ĐÚNG MỘT GIÂY. Khởi động ấm chỉ mất 1,7 giây nên không bao giờ
    chạm, và đó là lý do lỗi trông như ngẫu nhiên suốt nhiều tuần.
"""

from __future__ import annotations

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "shield" / "agent" / "__main__.py"
UNIT = ROOT / "systemd" / "shield-agent.service"


def _watchdog_source() -> str:
    source = AGENT.read_text(encoding="utf-8")
    start = source.index("async def watchdog_loop(")
    end = source.index("\nasync def ", start + 1)
    return source[start:end]


def test_the_first_ping_does_not_wait_a_whole_interval():
    """Bất biến trung tâm: có một ping TRƯỚC lần `sleep` đầu tiên."""
    body = _watchdog_source()
    first_notify = body.index('notify("WATCHDOG=1")')
    first_sleep = body.index("asyncio.sleep(interval)")
    assert first_notify < first_sleep, (
        "ping đầu tiên nằm sau cả một chu kỳ ngủ — đúng lỗi đã giết agent lúc boot")


def test_the_first_ping_still_proves_the_store_answers():
    """Ping sớm KHÔNG được là ping mù.

    Nới hạn hay ping vô điều kiện đều làm watchdog mất nghĩa: nó sẽ chỉ chứng
    minh "tiến trình còn tồn tại", đúng thứ `Restart=` đã bắt được rồi.
    """
    body = _watchdog_source()
    assert "get_baseline" in body, "ping không còn chứng minh store trả lời"
    tree = ast.parse(body.replace("async def watchdog_loop", "async def _wd", 1))
    guarded = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and "alive" in ast.dump(node):
            if 'WATCHDOG=1' in ast.dump(node):
                guarded += 1
    assert guarded >= 2, "phải có ping đầu VÀ ping trong vòng, cả hai đều có điều kiện"


def test_the_startup_budget_has_real_margin():
    """Ngân sách phải còn dư nhiều lần thời gian khởi động nguội đã đo (46 giây)."""
    unit = UNIT.read_text(encoding="utf-8")
    watchdog_s = int(re.search(r"^WatchdogSec=(\d+)", unit, re.MULTILINE).group(1))
    body = _watchdog_source()
    # Ping đầu xảy ra ngay sau khi store trả lời, nên ngân sách khởi động là
    # gần trọn `WatchdogSec` thay vì `WatchdogSec - interval`.
    assert watchdog_s >= 90, watchdog_s
    measured_cold_start_s = 46.0
    assert watchdog_s - measured_cold_start_s >= 40, (
        "biên khởi động nguội quá mỏng")


def test_the_fix_did_not_simply_raise_the_limit():
    """§8: không được sửa bằng cách nới `WatchdogSec`."""
    unit = UNIT.read_text(encoding="utf-8")
    watchdog_s = int(re.search(r"^WatchdogSec=(\d+)", unit, re.MULTILINE).group(1))
    assert watchdog_s == 90, f"WatchdogSec bị đổi thành {watchdog_s}"


def test_there_is_no_second_pinging_thread():
    """§8: không có luồng ping phụ nào che một deadlock thật."""
    body = _watchdog_source()
    for forbidden in ("threading.Thread", "Timer(", "daemon=True"):
        assert forbidden not in body, forbidden
    source = AGENT.read_text(encoding="utf-8")
    assert source.count('notify("WATCHDOG=1")') == 2, (
        "chỉ được có đúng hai chỗ ping: lần đầu và trong vòng")


def test_the_watchdog_schedules_on_a_monotonic_clock():
    """§5: đồng hồ tường nhảy lúc boot không được ảnh hưởng lịch ping."""
    body = _watchdog_source()
    assert "asyncio.sleep" in body
    for wall_clock in ("time.time()", "datetime.now(", "utcnow("):
        assert wall_clock not in body, wall_clock


def test_in_process_intervals_use_a_monotonic_clock():
    """Máy này đã quan sát được đồng hồ tường nhảy lùi ~10 giờ lúc boot."""
    discovery = (ROOT / "shield/agent/collectors/discovery.py").read_text(
        encoding="utf-8")
    assert "time.monotonic() - last_nmap" in discovery
    assert "time.time() - last_nmap" not in discovery

    health = (ROOT / "shield/security/health.py").read_text(encoding="utf-8")
    assert "time.monotonic() - self._started_monotonic" in health
