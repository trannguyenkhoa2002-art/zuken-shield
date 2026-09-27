"""Notifications stay bounded and redact secrets before any delivery."""

import asyncio
import logging

from shield.agent import notifier
from shield.common.models import Alert


def alert():
    return Alert(1.0, "TEST", "critical", "password=title-secret", "token=body-secret", "local")


class Process:
    def __init__(self, *, hangs=False, returncode=0):
        self.hangs = hangs
        self.returncode = None if hangs else returncode
        self.killed = False
        self.reaped = False

    async def communicate(self):
        if self.hangs and not self.killed:
            await asyncio.Event().wait()
        return b"", b"D-Bus unavailable password=stderr-secret"

    def kill(self):
        self.killed = True
        self.returncode = -9

    async def wait(self):
        self.reaped = True
        return self.returncode


def test_a_hung_desktop_sender_is_killed_and_reaped(monkeypatch):
    process = Process(hangs=True)

    async def spawn(*args, **kwargs):
        return process

    monkeypatch.setattr(notifier.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(notifier, "NOTIFY_TIMEOUT_S", 0.02, raising=False)

    async def scenario():
        assert await asyncio.wait_for(notifier._notify_send_as(None, alert()), 0.5) is False
        assert process.killed and process.reaped

    asyncio.run(scenario())


def test_desktop_delivery_redacts_the_message(monkeypatch):
    captured = []

    async def spawn(*args, **kwargs):
        captured.extend(args)
        return Process()

    monkeypatch.setattr(notifier.asyncio, "create_subprocess_exec", spawn)
    assert asyncio.run(notifier._notify_send_as(None, alert())) is True
    assert "title-secret" not in str(captured)
    assert "body-secret" not in str(captured)


def test_failed_desktop_delivery_has_an_actionable_redacted_warning(monkeypatch, caplog):
    async def spawn(*args, **kwargs):
        return Process(returncode=1)

    monkeypatch.setattr(notifier.asyncio, "create_subprocess_exec", spawn)
    with caplog.at_level(logging.WARNING, logger="shield.notifier"):
        assert asyncio.run(notifier._notify_send_as(None, alert())) is False
    assert "D-Bus unavailable" in caplog.text
    assert "stderr-secret" not in caplog.text


def test_telegram_is_opt_in_and_redacts_before_transport(monkeypatch):
    calls = []
    monkeypatch.delenv("SHIELD_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("SHIELD_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setattr(notifier, "_send_telegram_sync", lambda *args: calls.append(args) or 200)
    asyncio.run(notifier.notify_telegram(alert()))
    assert not calls
    monkeypatch.setenv("SHIELD_TELEGRAM_TOKEN", "synthetic-bot-token")
    monkeypatch.setenv("SHIELD_TELEGRAM_CHAT_ID", "synthetic-chat")
    asyncio.run(notifier.notify_telegram(alert()))
    assert len(calls) == 1
    assert "title-secret" not in calls[0][2]
    assert "body-secret" not in calls[0][2]


def test_transport_exception_cannot_log_the_telegram_credential(monkeypatch, caplog):
    token = "synthetic-bot-token"
    monkeypatch.setenv("SHIELD_TELEGRAM_TOKEN", token)
    monkeypatch.setenv("SHIELD_TELEGRAM_CHAT_ID", "synthetic-chat")
    monkeypatch.setattr(notifier, "_send_telegram_sync",
                        lambda *args: OSError(f"failure at https://api.telegram.org/bot{token}/sendMessage"))
    asyncio.run(notifier.notify_telegram(alert()))
    assert "Telegram" in caplog.text
    assert token not in caplog.text
