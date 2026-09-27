"""Thông báo khi có alert (KE-HOACH-SHIELD.md mục 2.4/1.4): notify-send (desktop,
tại chỗ) + Telegram Bot API (xa, khi không ngồi trước máy).

Không phải allowlist hành động (actions.py) — notifier chỉ gửi thông tin ra
ngoài, không đụng hệ thống hay mạng của người dùng. Chỉ thông báo alert
critical, theo tiêu chí nghiệm thu giai đoạn 4 (mục 5 kế hoạch) — info/warning
đã có trong tab Cảnh báo, thông báo push cho mọi mức sẽ làm bạn tắt nó đi.

Token Telegram đọc từ biến môi trường (SHIELD_TELEGRAM_TOKEN,
SHIELD_TELEGRAM_CHAT_ID) — Settings tab để nhập trong UI là giai đoạn 5.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import pwd
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from shield.common.models import Alert
from shield.common.secrets import redact_text

logger = logging.getLogger("shield.notifier")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
NOTIFY_TIMEOUT_S = 5.0


def desktop_session_uids() -> list[int]:
    """UID của các phiên desktop đang mở trên máy này.

    Agent chạy bằng ROOT dưới systemd, mà `notify-send` gửi thông báo qua
    D-Bus của PHIÊN NGƯỜI DÙNG — chạy thẳng bằng root thì thông báo không
    tới đâu cả (không lỗi, chỉ im lặng biến mất). Đây là lý do thông báo
    desktop trước đây không bao giờ hiện dù log ghi là đã gửi.

    Cách nhận biết phiên đang mở: thư mục `/run/user/<uid>` có socket `bus`
    — systemd tạo cái này cho mỗi phiên đăng nhập có D-Bus, và xoá khi đăng
    xuất, nên không cần gọi thêm `loginctl`.
    """
    uids: list[int] = []
    run_user = Path("/run/user")
    if not run_user.is_dir():
        return uids
    try:
        for entry in run_user.iterdir():
            if not entry.name.isdigit():
                continue
            if (entry / "bus").exists():
                uids.append(int(entry.name))
    except OSError as e:
        logger.debug("Không liệt kê được /run/user: %s", e)
    return uids


async def _notify_send_as(uid: int | None, alert: Alert) -> bool:
    """Chạy notify-send. `uid=None` nghĩa là chạy bằng chính user hiện tại
    (chế độ dev, agent không chạy bằng root)."""
    args = ["/usr/bin/notify-send", "-u", "critical",
            f"Shield: {redact_text(alert.title)}", redact_text(alert.detail)]
    env = dict(os.environ)
    if uid is not None:
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
        env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
        # setpriv có sẵn trong util-linux (mọi bản Debian/Ubuntu/Kali), không
        # cần sudo và không đọc file cấu hình nào — phù hợp chạy từ daemon.
        try:
            gid = pwd.getpwuid(uid).pw_gid
        except KeyError:
            logger.warning("Không tìm thấy tài khoản desktop uid=%s", uid)
            return False
        args = ["/usr/bin/setpriv", "--reuid", str(uid), "--regid", str(gid), "--init-groups", *args]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), NOTIFY_TIMEOUT_S)
        if proc.returncode != 0:
            logger.warning(
                "notify-send (uid=%s) trả về %s: %s",
                uid, proc.returncode, redact_text(stderr.decode(errors="replace").strip())[:500],
            )
            return False
        return True
    except FileNotFoundError as e:
        logger.warning("Thiếu lệnh để gửi thông báo desktop: %s", e.filename)
        return False
    except TimeoutError:
        logger.warning("notify-send (uid=%s) quá hạn %.1fs; kiểm tra D-Bus của phiên desktop", uid, NOTIFY_TIMEOUT_S)
        return False
    except Exception as exc:
        logger.warning("Lỗi gửi notify-send (uid=%s): %s", uid, type(exc).__name__)
        return False
    finally:
        # Includes caller cancellation: never leave a blocked sender behind.
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(proc.wait(), 1.0)


async def notify_desktop(alert: Alert) -> None:
    if os.geteuid() != 0:
        await _notify_send_as(None, alert)
        return

    uids = desktop_session_uids()
    if not uids:
        logger.debug("Không thấy phiên desktop nào đang mở — bỏ qua thông báo desktop.")
        return
    # Gửi cho mọi phiên đang mở: máy có thể có nhiều user đăng nhập cùng lúc
    # (fast user switching), không đoán được ai đang ngồi trước máy.
    results = await asyncio.gather(*(_notify_send_as(uid, alert) for uid in uids))
    if not any(results):
        logger.warning(
            "Không gửi được thông báo desktop tới phiên nào (%s) — xem lỗi notify-send phía trên.",
            uids,
        )


def _send_telegram_sync(token: str, chat_id: str, text: str) -> int | Exception:
    url = TELEGRAM_API.format(token=token)
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except (urllib.error.URLError, OSError) as e:
        return e


async def notify_telegram(alert: Alert) -> None:
    token = os.environ.get("SHIELD_TELEGRAM_TOKEN")
    chat_id = os.environ.get("SHIELD_TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        logger.debug("Chưa cấu hình SHIELD_TELEGRAM_TOKEN/SHIELD_TELEGRAM_CHAT_ID — bỏ qua.")
        return

    text = redact_text(f"🛑 Shield [{alert.severity.upper()}] {alert.title}\n{alert.detail}")
    result = await asyncio.to_thread(_send_telegram_sync, token, chat_id, text)
    if isinstance(result, Exception):
        # HTTP/URL exceptions can include the credential embedded in the URL.
        reason = redact_text(str(result).replace(token, "[đã che]"))[:500]
        logger.error("Gửi Telegram thất bại (%s): %s", type(result).__name__, reason)
    elif result != 200:
        logger.error("Telegram trả về status %s", result)
    else:
        logger.info("Đã gửi thông báo Telegram cho alert %s", alert.rule_id)


async def notify(alert: Alert, force: bool = False) -> None:
    """Chỉ thông báo alert critical (tiêu chí giai đoạn 4: 'critical -> Telegram <10s').

    `force=True` dành cho vấn đề của chính Shield (shield/agent/problems.py):
    collector chết hay log đang bị rớt không mang mức `critical` nhưng vẫn phải
    tới được người dùng ngay. Những cái đó đã chặn trùng ở ProblemReporter.
    """
    if alert.severity != "critical" and not force:
        return
    await asyncio.gather(notify_desktop(alert), notify_telegram(alert))


async def notify_text(message: str, title: str = "Shield") -> None:
    """Thông báo một dòng chữ, không gắn với alert nào.

    Dùng cho tin "đã hết vấn đề": nó không phải một alert, không nên nằm trong
    lịch sử cảnh báo, nhưng vẫn phải tới được người đã nhận tin xấu trước đó —
    thông báo chỉ biết kêu mà không bao giờ nói "đã ổn" thì lần sau không ai đọc.
    """
    resolved = Alert(0.0, "SHIELD_PROBLEM_RESOLVED", "warning", title, message, "shield")
    await asyncio.gather(notify_desktop(resolved), notify_telegram(resolved))
