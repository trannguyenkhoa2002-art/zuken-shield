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
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Awaitable, Callable

from shield.common.models import Alert
from shield.common.secrets import redact_text

logger = logging.getLogger("shield.notifier")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
NOTIFY_TIMEOUT_S = 5.0


# Kênh thông báo desktop khi agent chạy bằng root (systemd).
#
# Trước đây agent tự đổi sang UID của người dùng (`setpriv --reuid`) rồi gọi
# notify-send trên D-Bus của phiên đó. Dưới hardening của unit (seccomp của
# RestrictSUIDSGID/ProtectKernelLogs, NoNewPrivileges) lời gọi setresuid bị
# chặn: journal ghi `setpriv: setresuid failed: Operation not permitted` ở MỌI
# lần gửi từ 11/09 tới 25/09/2026, tức không một thông báo desktop nào tới
# được người dùng — kể cả lúc agent chết. Nới hardening để ép nó chạy là đổi
# an toàn lấy tiện lợi.
#
# Giờ không có chuyển quyền nào: agent phát thông báo (đã che bí mật) qua IPC,
# và `shield-notify` — một systemd user service chạy SẴN trong phiên người
# dùng — nhận rồi gọi notify-send bằng chính quyền của người đó. Xem
# shield/notify_bridge.py.
_desktop_relay: Callable[[dict], Awaitable[int]] | None = None


def set_desktop_relay(relay: Callable[[dict], Awaitable[int]] | None) -> None:
    """Agent đăng ký hàm phát thông báo qua IPC; trả về số phiên đã nhận."""
    global _desktop_relay
    _desktop_relay = relay


def desktop_payload(alert: Alert) -> dict:
    """Nội dung thông báo desktop, ĐÃ CHE bí mật trước khi rời agent."""
    return {
        "title": f"Shield: {redact_text(alert.title)}",
        "body": redact_text(alert.detail),
        "severity": alert.severity,
        "rule_id": alert.rule_id,
    }


async def run_notify_send(title: str, body: str, *, urgency: str = "critical") -> bool:
    """Chạy notify-send bằng chính user hiện tại, có hạn thời gian.

    Dùng ở hai chỗ: agent chạy không phải root (chế độ dev) và
    `shield-notify` trong phiên người dùng.
    """
    args = ["/usr/bin/notify-send", "-u", urgency, redact_text(title), redact_text(body)]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), NOTIFY_TIMEOUT_S)
        if proc.returncode != 0:
            logger.warning(
                "notify-send trả về %s: %s",
                proc.returncode, redact_text(stderr.decode(errors="replace").strip())[:500],
            )
            return False
        return True
    except FileNotFoundError as e:
        logger.warning("Thiếu lệnh để gửi thông báo desktop: %s", e.filename)
        return False
    except TimeoutError:
        logger.warning("notify-send quá hạn %.1fs; kiểm tra D-Bus của phiên desktop", NOTIFY_TIMEOUT_S)
        return False
    except Exception as exc:
        logger.warning("Lỗi gửi notify-send: %s", type(exc).__name__)
        return False
    finally:
        # Includes caller cancellation: never leave a blocked sender behind.
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(proc.wait(), 1.0)


async def notify_desktop_as_user(alert: Alert) -> bool:
    """Hiện thông báo cho một alert bằng quyền của tiến trình hiện tại."""
    payload = desktop_payload(alert)
    return await run_notify_send(payload["title"], payload["body"])


async def notify_desktop(alert: Alert) -> None:
    if os.geteuid() != 0:
        await notify_desktop_as_user(alert)
        return
    payload = desktop_payload(alert)
    if _desktop_relay is None:
        logger.warning("Chưa có kênh thông báo desktop — bỏ qua thông báo %s.", alert.rule_id)
        return
    delivered = await _desktop_relay(payload)
    if not delivered:
        # Nói thẳng lý do và cách sửa: im lặng ở đây chính là lỗi cũ.
        logger.warning(
            "Không có phiên desktop nào đang chạy shield-notify — thông báo %s không tới "
            "được người dùng. Bật bằng: systemctl --user enable --now shield-notify.service "
            "(user phải thuộc nhóm shield).",
            alert.rule_id,
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
