"""Thông báo desktop đi qua shield-notify trong phiên người dùng.

Trước đây agent root tự `setpriv --reuid` rồi gọi notify-send; dưới hardening
của unit, lời gọi setresuid bị chặn và journal ghi `setresuid failed:
Operation not permitted` ở mọi lần gửi (11/09–25/09/2026). Không một thông báo
nào tới người dùng — kể cả khi agent chết hẳn ngày 27/09.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path

from shield import notify_bridge
from shield.agent import notifier
from shield.agent.ipc import SUBSCRIBE_NOTIFICATIONS, IpcServer
from shield.common.models import Alert

ROOT = Path(__file__).resolve().parent.parent


def _alert():
    return Alert(1.0, "TEST_RULE", "critical", "password=title-secret", "token=body-secret", "local")


def test_the_agent_no_longer_switches_user_to_notify():
    source = (ROOT / "shield/agent/notifier.py").read_text(encoding="utf-8")
    assert '"/usr/bin/setpriv"' not in source
    assert "--reuid" not in source.replace("`setpriv --reuid`", "")


def test_root_agent_relays_a_redacted_payload(monkeypatch):
    sent = []

    async def relay(payload):
        sent.append(payload)
        return 1

    monkeypatch.setattr(notifier.os, "geteuid", lambda: 0)
    notifier.set_desktop_relay(relay)
    try:
        asyncio.run(notifier.notify_desktop(_alert()))
    finally:
        notifier.set_desktop_relay(None)
    assert len(sent) == 1
    assert "title-secret" not in json.dumps(sent)
    assert "body-secret" not in json.dumps(sent)
    assert sent[0]["rule_id"] == "TEST_RULE"


def test_nobody_listening_is_reported_not_swallowed(monkeypatch, caplog):
    async def relay(payload):
        return 0

    monkeypatch.setattr(notifier.os, "geteuid", lambda: 0)
    notifier.set_desktop_relay(relay)
    try:
        with caplog.at_level(logging.WARNING, logger="shield.notifier"):
            asyncio.run(notifier.notify_desktop(_alert()))
    finally:
        notifier.set_desktop_relay(None)
    assert "shield-notify" in caplog.text


def test_agent_loss_is_reported_once_after_the_grace_period():
    watch = notify_bridge.AgentWatch(grace_s=120, now=0.0)
    assert not watch.should_report_loss(60.0), "một lần restart bình thường không được báo động"
    assert watch.should_report_loss(121.0)
    assert not watch.should_report_loss(500.0), "chỉ báo một lần"
    assert watch.connected() is True, "nối lại sau khi đã báo mất thì phải báo phục hồi"
    assert watch.connected() is False


def test_a_quick_reconnect_is_silent():
    watch = notify_bridge.AgentWatch(grace_s=120, now=0.0)
    assert watch.connected() is False
    watch.disconnected(10.0)
    assert not watch.should_report_loss(40.0)
    assert watch.connected() is False


def test_the_bridge_only_shows_well_formed_notifications(monkeypatch):
    shown = []

    async def fake_send(title, body, urgency="critical"):
        shown.append((title, body))
        return True

    monkeypatch.setattr(notify_bridge, "run_notify_send", fake_send)
    lines = [
        b"not json\n",
        json.dumps({"type": "alert", "data": {"title": "x", "body": "y"}}).encode(),
        json.dumps({"type": "desktop_notification", "data": {"title": 1, "body": "y"}}).encode(),
        json.dumps({"type": "desktop_notification", "data": {"title": "T", "body": "B"}}).encode(),
    ]
    results = [asyncio.run(notify_bridge.handle_line(line)) for line in lines]
    assert results == [False, False, False, True]
    assert shown == [("T", "B")]


def test_end_to_end_over_a_real_unix_socket(monkeypatch):
    """IPC thật: bridge đăng ký, agent gửi, bridge hiện — không cần root."""
    shown = []

    async def fake_send(title, body, urgency="critical"):
        shown.append((title, body))
        return True

    monkeypatch.setattr(notify_bridge, "run_notify_send", fake_send)

    async def scenario(sock):
        server = IpcServer(sock)
        await server.start()
        watch = notify_bridge.AgentWatch(grace_s=120)
        task = asyncio.create_task(notify_bridge.session(sock, watch))
        for _ in range(100):
            if server._notification_clients:
                break
            await asyncio.sleep(0.02)
        delivered = await server.send_desktop_notification(
            notifier.desktop_payload(_alert()))
        for _ in range(100):
            if shown:
                break
            await asyncio.sleep(0.02)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await server.close()
        return delivered

    with tempfile.TemporaryDirectory() as directory:
        sock = Path(directory) / "shield.sock"
        delivered = asyncio.run(scenario(sock))
    assert delivered == 1
    assert len(shown) == 1
    assert "title-secret" not in shown[0][0]
    assert "body-secret" not in shown[0][1]


def test_subscription_is_an_ipc_level_command():
    assert SUBSCRIBE_NOTIFICATIONS == "subscribe_desktop_notifications"


def test_the_user_unit_is_packaged_and_enabled():
    unit = (ROOT / "systemd/user/shield-notify.service").read_text(encoding="utf-8")
    assert "ExecStart=/opt/shield/.venv/bin/shield-notify" in unit
    assert "User=" not in unit, "user unit chạy bằng chính user của phiên"
    build = (ROOT / "packaging/build-deb.sh").read_text(encoding="utf-8")
    assert "usr/lib/systemd/user/shield-notify.service" in build
    postinst = (ROOT / "packaging/debian/postinst").read_text(encoding="utf-8")
    assert "systemctl --global enable shield-notify.service" in postinst
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'shield-notify = "shield.notify_bridge:main"' in pyproject
