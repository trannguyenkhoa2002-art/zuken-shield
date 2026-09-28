"""Regression checks from the 2026-09-11 audit, including real local sockets."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time

import pytest

from packet_helper import protocol as helper_protocol
from shield.agent.bus import Bus
from shield.agent.collectors import packet_ingest as ingest
from shield.agent.collectors import packet_protocol as core_protocol
from shield.agent.store import Store


def message(**changes):
    result = {"version": 1, "event_type": "arp_reply", "collector": "arp_sniffer",
              "timestamp": time.time(), "payload": {"ip": "192.0.2.44"}}
    result.update(changes)
    return json.dumps(result).encode()


@pytest.mark.parametrize("value", [[], {}, ["arp_reply"], None, True, 17])
def test_non_string_event_types_are_rejected(value):
    assert ingest.parse_line(message(event_type=value)) is None


@pytest.mark.parametrize("value", [True, 1.0, "1", None])
def test_version_requires_an_integer(value):
    assert ingest.parse_line(message(version=value)) is None


def test_nested_json_is_rejected_without_exhausting_the_parser_stack():
    raw = b'{"version":1,"payload":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}'
    assert len(raw) < core_protocol.MAX_LINE_BYTES
    assert ingest.parse_line(raw) is None


def test_a_timestamp_too_large_for_float_is_rejected():
    assert ingest.parse_line(message(timestamp=10**1000)) is None


@pytest.mark.parametrize("protocol", [core_protocol, helper_protocol])
@pytest.mark.parametrize("value", [":::", "1:2:3", "1::2::3", "fe80::1%eth0", "999.1.1.1", 1, True])
def test_invalid_addresses_cannot_enter_either_side(protocol, value):
    assert protocol.valid_ip(value) is False
    assert protocol.clean_payload({"ip": value}) is None


@pytest.mark.parametrize("protocol", [core_protocol, helper_protocol])
@pytest.mark.parametrize("value", ["::1", "2001:db8::1", "::ffff:192.0.2.1", "192.0.2.1"])
def test_valid_addresses_remain_supported(protocol, value):
    assert protocol.clean_payload({"ip": value}) == {"ip": value}


def test_bad_json_does_not_hide_the_next_valid_event(tmp_path):
    async def scenario():
        path = str(tmp_path / "helper.sock")
        bus, health = Bus(), ingest.PacketIngestHealth()
        queue = bus.subscribe()

        async def send(reader, writer):
            try:
                writer.write(message(event_type=[]) + b"\n" + message() + b"\n")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_unix_server(send, path=path):
            await asyncio.wait_for(ingest.ingest_loop(bus, socket_path=path, health=health, retry=False), 2)
        assert health.rejected == 1
        assert health.accepted == 1
        assert health.last_error
        assert queue.get_nowait().data["ip"] == "192.0.2.44"
        assert queue.empty()

    asyncio.run(scenario())


@pytest.mark.parametrize("payload", [b"x" * 70000 + b"\n", b"x" * 70000], ids=["terminated", "unterminated"])
def test_oversized_stream_is_counted_and_reconnect_recovers(tmp_path, monkeypatch, payload):
    monkeypatch.setattr(ingest, "RECONNECT_DELAY_S", 0.01)

    async def scenario():
        path = str(tmp_path / "helper.sock")
        bus, health = Bus(), ingest.PacketIngestHealth()
        queue = bus.subscribe()
        connections = 0
        handlers = set()
        release = asyncio.Event()

        async def send(reader, writer):
            nonlocal connections
            task = asyncio.current_task()
            handlers.add(task)
            connections += 1
            try:
                writer.write(payload if connections == 1 else message() + b"\n")
                await writer.drain()
                await release.wait()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()
                with contextlib.suppress(ConnectionError, OSError):
                    await writer.wait_closed()
                handlers.discard(task)

        store = Store(tmp_path / "health.db")
        try:
            async with await asyncio.start_unix_server(send, path=path):
                task = asyncio.create_task(ingest.ingest_loop(bus, socket_path=path, health=health, store=store))
                try:
                    event = await asyncio.wait_for(queue.get(), 2)
                    assert event.kind == "arp_reply"
                    assert health.rejected == 1
                    assert health.accepted == 1
                    assert health.connects == 2
                    assert "oversized" in health.last_error
                finally:
                    release.set()
                    task.cancel()
                    try:
                        with contextlib.suppress(asyncio.CancelledError):
                            await asyncio.wait_for(task, 1)
                    finally:
                        if handlers:
                            await asyncio.wait_for(asyncio.gather(*handlers), 1)
            assert not health.connected
            row = store.conn.execute("SELECT healthy,state FROM collector_health WHERE component='packet_ingest'").fetchone()
            assert row == (0, "stopped")
        finally:
            store.close()

    asyncio.run(scenario())


def test_cancellation_during_connect_is_not_swallowed(tmp_path, monkeypatch):
    path = tmp_path / "exists.sock"
    path.touch()

    async def cancel_connect(*args, **kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "open_unix_connection", cancel_connect)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(ingest.ingest_loop(Bus(), socket_path=str(path), retry=False))
