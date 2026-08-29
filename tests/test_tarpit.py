"""Test tarpit — parser thuần + hành vi accept/drip/cleanup thật (dùng cổng
loopback cục bộ, không cần root, không đụng mạng ngoài).

Chạy async test bằng `asyncio.run()` trực tiếp thay vì pytest-asyncio — dự
án không có dependency đó, và test ở đây đơn giản, không cần fixture async
phức tạp.
"""

from __future__ import annotations

import asyncio
import socket

from shield.agent import tarpit


def run(coro):
    return asyncio.run(coro)


# --- parse_port_list ---


def test_parse_port_list_basic():
    assert tarpit.parse_port_list("2222, 4444,8081") == [2222, 4444, 8081]


def test_parse_port_list_ignores_junk_and_out_of_range():
    assert tarpit.parse_port_list("2222, abc, 99999, 0, -5, 4444") == [2222, 4444]


def test_parse_port_list_dedupes_keeps_order():
    assert tarpit.parse_port_list("80,443,80") == [80, 443]


def test_parse_port_list_empty():
    assert tarpit.parse_port_list("") == []
    assert tarpit.parse_port_list("   ") == []


# --- TarpitManager: hành vi thật trên loopback ---


def test_manager_accepts_and_drips_data():
    async def scenario():
        tarpit.DRIP_INTERVAL_S = 0.05
        mgr = tarpit.TarpitManager()
        events = []
        mgr._on_new_connection = lambda info: events.append(info)

        opened, failed = await mgr.start([0])  # port=0 -> OS tự cấp cổng trống
        assert failed == []
        real_port = mgr.active_ports[0]

        reader, writer = await asyncio.open_connection("127.0.0.1", real_port)
        # read(n) trả về ngay khi có BẤT KỲ dữ liệu nào (có thể <n byte) —
        # cần readexactly để chắc chắn đã nhận đủ 2 lần nhỏ giọt.
        data = await asyncio.wait_for(reader.readexactly(2), timeout=2.0)
        assert data == tarpit.DRIP_BYTE * 2

        conns = mgr.list_connections()
        assert len(conns) == 1
        assert conns[0]["ip"] == "127.0.0.1"
        assert len(events) == 1

        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.3)
        assert mgr.list_connections() == []  # dọn dẹp sau khi client tự ngắt

        await mgr.stop_all()
        assert mgr.active_ports == []

    run(scenario())


def test_manager_start_is_idempotent_for_already_open_port():
    async def scenario():
        mgr = tarpit.TarpitManager()
        await mgr.start([0])
        port = mgr.active_ports[0]
        opened2, failed2 = await mgr.start([port])
        assert failed2 == []
        assert opened2 == [port]
        assert len(mgr._servers) == 1
        await mgr.stop_all()

    run(scenario())


def test_manager_reports_failed_port_without_crashing():
    """Cổng đã bị dịch vụ khác chiếm -> start() trả lỗi cho CỔNG ĐÓ, không
    ném exception làm dừng cả tarpit."""
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    blocked_port = blocker.getsockname()[1]

    async def scenario():
        mgr = tarpit.TarpitManager()
        opened, failed = await mgr.start([blocked_port])
        assert opened == []
        assert len(failed) == 1
        assert failed[0][0] == blocked_port
        await mgr.stop_all()

    try:
        run(scenario())
    finally:
        blocker.close()


def test_max_connections_per_ip_enforced():
    """1 IP không được chiếm quá MAX_CONNECTIONS_PER_IP slot — kết nối vượt
    của chính nó bị đóng ngay, chừa chỗ cho nguồn khác."""

    async def scenario():
        tarpit.MAX_CONNECTIONS_PER_IP = 2
        tarpit.DRIP_INTERVAL_S = 0.5
        mgr = tarpit.TarpitManager()
        await mgr.start([0])
        port = mgr.active_ports[0]

        held = []
        for _ in range(2):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.wait_for(r.read(1), timeout=2.0)
            held.append((r, w))

        # Kết nối thứ 3 từ cùng IP (127.0.0.1) vượt trần -> bị đóng ngay (EOF).
        r3, w3 = await asyncio.open_connection("127.0.0.1", port)
        data = await asyncio.wait_for(r3.read(1), timeout=2.0)
        assert data == b""
        assert len(mgr.list_connections()) == 2

        for _, w in held:
            w.close()
        w3.close()
        await mgr.stop_all()

    run(scenario())


def test_manager_stop_all_clears_state():
    async def scenario():
        mgr = tarpit.TarpitManager()
        await mgr.start([0, 0])
        assert len(mgr.active_ports) == 2
        await mgr.stop_all()
        assert mgr.active_ports == []
        assert mgr.list_connections() == []

    run(scenario())


def test_max_concurrent_connections_enforced():
    """Vượt MAX_CONCURRENT_CONNECTIONS -> kết nối thừa bị đóng ngay, không
    làm crash server hay tràn bộ nhớ theo dõi kết nối."""

    async def scenario():
        tarpit.MAX_CONCURRENT_CONNECTIONS_ORIG = tarpit.MAX_CONCURRENT_CONNECTIONS
        tarpit.MAX_CONCURRENT_CONNECTIONS = 1
        tarpit.DRIP_INTERVAL_S = 0.5
        try:
            mgr = tarpit.TarpitManager()
            await mgr.start([0])
            port = mgr.active_ports[0]

            r1, w1 = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.wait_for(r1.read(1), timeout=2.0)  # đợi kết nối 1 được nhận + ghi nhận

            r2, w2 = await asyncio.open_connection("127.0.0.1", port)
            # Kết nối thứ 2 vượt giới hạn -> server đóng ngay, read() trả rỗng (EOF).
            data2 = await asyncio.wait_for(r2.read(1), timeout=2.0)
            assert data2 == b""

            assert len(mgr.list_connections()) == 1
            w1.close()
            w2.close()
            await mgr.stop_all()
        finally:
            tarpit.MAX_CONCURRENT_CONNECTIONS = tarpit.MAX_CONCURRENT_CONNECTIONS_ORIG

    run(scenario())


def test_bind_host_defaults_to_all_interfaces_and_honours_env(monkeypatch):
    """Mặc định 0.0.0.0 (máy LAN cần mồi nhìn thấy được từ mạng nội bộ), nhưng
    máy có IP public thì đặt SHIELD_TARPIT_BIND để không phơi cổng mồi ra
    Internet. Kiểm bằng địa chỉ socket thật đã bind, không phải thuộc tính."""
    monkeypatch.delenv("SHIELD_TARPIT_BIND", raising=False)
    assert tarpit.TarpitManager().bind_host == "0.0.0.0"

    monkeypatch.setenv("SHIELD_TARPIT_BIND", "127.0.0.1")

    async def scenario():
        mgr = tarpit.TarpitManager()
        assert mgr.bind_host == "127.0.0.1"
        opened, failed = await mgr.start([0])
        assert failed == []
        bound_host = mgr._servers[opened[0]].sockets[0].getsockname()[0]
        await mgr.stop_all()
        return bound_host

    assert asyncio.run(scenario()) == "127.0.0.1"


def test_public_ipv4_addresses_ignores_private_and_loopback():
    """Cảnh báo phơi nhiễm chỉ được kích hoạt bởi địa chỉ định tuyến công cộng."""
    for addr in tarpit.public_ipv4_addresses():
        assert not addr.startswith(("10.", "127.", "192.168.", "169.254."))
