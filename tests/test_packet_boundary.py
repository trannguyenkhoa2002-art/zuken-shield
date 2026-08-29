"""Ranh giới scapy: lõi Shield không được import nó, dù chỉ một lần.

Lý do là giấy phép. scapy là GPL-2.0; lõi Shield nhắm Apache-2.0. Việc bắt gói
nằm ở `shield-packet-collector`, một chương trình riêng, một gói cài riêng, một
tiến trình riêng. Bài test này là thứ giữ cho ranh giới đó không trôi đi khi có
người thêm "chỉ một import nhỏ" vào lõi.

Việc tách là KIẾN TRÚC, không phải một kết luận pháp lý — xem NOTICE.
"""

from __future__ import annotations

import ast
import json
import pathlib
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE = ROOT / "shield"


def _imported_modules(path: pathlib.Path) -> set[str]:
    """Mọi module được import trong file, kể cả import nằm trong hàm."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


# --- §12 bất biến nguồn -------------------------------------------------


def test_the_core_never_imports_scapy():
    """Quét AST, không grep: một `import` trong thân hàm cũng là một import."""
    offenders = []
    for path in sorted(CORE.rglob("*.py")):
        if "scapy" in _imported_modules(path):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"lõi import scapy: {offenders}"


def test_only_the_helper_imports_scapy():
    helper = ROOT / "packet_helper"
    importers = [str(p.relative_to(ROOT)) for p in sorted(helper.rglob("*.py"))
                 if "scapy" in _imported_modules(p)]
    assert importers, "helper phải là nơi DUY NHẤT import scapy"
    for path in importers:
        assert path.startswith("packet_helper/"), path


def test_the_helper_never_imports_shield_core():
    """Ranh giới hai chiều: helper cũng không được kéo lõi vào."""
    for path in sorted((ROOT / "packet_helper").rglob("*.py")):
        assert "shield" not in _imported_modules(path), path


def test_the_core_package_does_not_depend_on_scapy():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dependencies = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert "scapy" not in dependencies, dependencies


def test_the_core_debian_package_does_not_depend_on_scapy():
    control = (ROOT / "packaging/debian/control").read_text(encoding="utf-8")
    depends = [line for line in control.splitlines() if line.startswith("Depends:")][0]
    assert "scapy" not in depends, depends
    assert "shield-packet-collector" in control, "gói tuỳ chọn phải được gợi ý"


def test_the_helper_package_declares_its_own_dependency():
    text = (ROOT / "packaging/packet-collector/pyproject.toml").read_text(
        encoding="utf-8")
    assert "scapy" in text
    control = (ROOT / "packaging/packet-collector/control").read_text(encoding="utf-8")
    assert "python3-scapy" in control


# --- §11 tương thích sự kiện --------------------------------------------


def test_the_helper_can_only_emit_event_types_the_core_knows():
    from packet_helper.protocol import OBSERVATIONS

    for observation, (source, kind) in OBSERVATIONS.items():
        assert source in {"arp_sniffer", "conn_watch", "dns_watch"}, source
        assert kind, observation


def test_helper_output_becomes_the_same_event_the_old_collector_emitted():
    """§11: detector phía sau không được phân biệt nguồn.

    Bản ghi kỳ vọng dưới đây là hình dạng Event mà vòng sniff cũ phát ra:
    `source="arp_sniffer"`, `kind="arp_reply"`, `data={"ip":…, "mac":…}`.
    """
    from packet_helper.protocol import envelope
    from shield.agent.collectors.packet_ingest import parse_line

    payload = {"ip": "192.0.2.44", "mac": "aa:bb:cc:dd:ee:ff"}
    line = json.dumps(envelope("arp_reply", payload, time.time())).encode()
    source, kind, data, _ts = parse_line(line)
    assert (source, kind) == ("arp_sniffer", "arp_reply")
    assert data == payload

    line = json.dumps(envelope("tcp_syn", {"src_ip": "192.0.2.9", "dst_port": 22},
                               time.time())).encode()
    source, kind, data, _ts = parse_line(line)
    assert (source, kind) == ("conn_watch", "tcp_syn")
    assert data == {"src_ip": "192.0.2.9", "dst_port": 22}


# --- §4 helper là ĐẦU VÀO KHÔNG TIN CẬY ---------------------------------


@pytest.mark.parametrize("raw", [
    b"", b"{", b"not json", b"[]", b"null", b'{"version":1}',
    json.dumps({"version": 2, "collector": "arp_sniffer", "event_type": "arp_reply",
                "timestamp": 0, "payload": {}}).encode(),
    json.dumps({"version": 1, "collector": "arp_sniffer", "event_type": "rm -rf /",
                "timestamp": 0, "payload": {}}).encode(),
    json.dumps({"version": 1, "collector": "traffic", "event_type": "arp_reply",
                "timestamp": 0, "payload": {}}).encode(),
    b"x" * 9000,
])
def test_malformed_helper_output_is_dropped(raw):
    from shield.agent.collectors.packet_ingest import parse_line

    assert parse_line(raw) is None


@pytest.mark.parametrize("payload", [
    {"ip": "999.999.999.999"}, {"ip": "'; DROP TABLE events;--"},
    {"mac": "not-a-mac"}, {"dst_port": "22"}, {"dst_port": -1},
    {"dst_port": 2**40}, {"interface": "x" * 500},
    {"known": ["a"] * 100}, {"ip": {"nested": "object"}},
])
def test_hostile_payload_values_are_rejected(payload):
    from packet_helper.protocol import envelope

    from shield.agent.collectors.packet_ingest import parse_line

    line = json.dumps({"version": 1, "collector": "arp_sniffer",
                       "event_type": "arp_reply", "timestamp": time.time(),
                       "payload": payload}).encode()
    parsed = parse_line(line)
    assert parsed is None or all(key in {"ip", "mac", "dst_port", "interface",
                                         "known"} for key in parsed[2])
    if parsed is not None:
        assert "DROP TABLE" not in json.dumps(parsed[2])


def test_a_timestamp_outside_the_sane_window_is_rejected():
    from packet_helper.protocol import envelope

    from shield.agent.collectors.packet_ingest import parse_line

    for offset in (-86400, +3600):
        line = json.dumps(envelope("arp_reply", {"ip": "192.0.2.1"},
                                   time.time() + offset)).encode()
        assert parse_line(line) is None, offset


def test_the_helper_cannot_reach_response_or_the_database():
    """Helper không được có đường tới hành động, token, hay DB."""
    for path in sorted((ROOT / "packet_helper").rglob("*.py")):
        modules = _imported_modules(path)
        for forbidden in ("sqlite3", "shield", "subprocess"):
            assert forbidden not in modules, (path.name, forbidden)
        source = path.read_text(encoding="utf-8")
        for word in ("CapabilityToken", "block_ip", "isolate_endpoint",
                     "stop_process", "os.system", "eval(", "exec("):
            assert word not in source, (path.name, word)


# --- §7 lõi vẫn dùng được khi helper vắng mặt ---------------------------


def test_the_core_runs_without_the_helper(tmp_path):
    from shield.agent.collectors.packet_ingest import collector_status

    status = collector_status(socket_path=str(tmp_path / "absent.sock"))
    assert status["running"] is False
    assert status["available"] is False
    assert set(status) == {"installed", "running", "available", "version",
                           "last_event", "health"}


def test_missing_helper_is_reported_not_fatal(tmp_path):
    import asyncio

    from shield.agent.bus import Bus
    from shield.agent.collectors.packet_ingest import (PacketIngestHealth,
                                                       ingest_loop)

    health = PacketIngestHealth()
    asyncio.run(ingest_loop(Bus(), socket_path=str(tmp_path / "absent.sock"),
                            health=health, retry=False))
    assert health.connected is False
    assert "chưa chạy" in health.last_error


def test_a_stale_socket_file_does_not_wedge_the_core(tmp_path):
    import asyncio

    from shield.agent.bus import Bus
    from shield.agent.collectors.packet_ingest import (PacketIngestHealth,
                                                       ingest_loop)

    stale = tmp_path / "stale.sock"
    stale.write_text("not really a socket")     # file tồn tại nhưng không nối được
    health = PacketIngestHealth()
    asyncio.run(ingest_loop(Bus(), socket_path=str(stale), health=health, retry=False))
    assert health.connected is False and health.last_error


# --- §10 cô lập hỏng hóc ------------------------------------------------


def test_a_flood_of_events_is_bounded():
    from shield.agent.collectors.packet_ingest import MAX_EVENTS_PER_S

    assert 0 < MAX_EVENTS_PER_S <= 10_000


def test_the_helper_queue_is_bounded():
    from packet_helper.__main__ import MAX_QUEUE, Publisher

    assert 0 < MAX_QUEUE <= 10_000
    publisher = Publisher()
    queue = publisher.subscribe()
    for _ in range(MAX_QUEUE + 50):
        publisher.publish("arp_reply", {"ip": "192.0.2.1", "mac": "aa:bb:cc:dd:ee:ff"})
    assert queue.qsize() <= MAX_QUEUE
    assert publisher.dropped > 0, "hàng đợi đầy mà không đếm gói bị bỏ"


# --- hai bản sao hợp đồng phải KHÔNG được trôi khỏi nhau ------------------


def test_the_core_does_not_import_the_helper_package():
    """Lõi phải chạy được khi gói helper KHÔNG được cài.

    Bản trước import `packet_helper.protocol` ở mức module, nên một bản cài
    CHỈ LÕI đổ ngay lúc import — đúng thứ mà việc tách ra lẽ ra phải ngăn. Máy
    phát triển không lộ ra vì cả hai cây mã đều nằm cạnh nhau; một container
    Ubuntu sạch lộ ra ngay lần cài đầu.
    """
    for path in sorted(CORE.rglob("*.py")):
        assert "packet_helper" not in _imported_modules(path), path


def test_the_two_protocol_copies_agree():
    """Hai bản sao là CỐ Ý (ranh giới giấy phép), nên phải có người canh chúng."""
    from packet_helper import protocol as helper_side
    from shield.agent.collectors import packet_protocol as core_side

    assert core_side.SCHEMA_VERSION == helper_side.SCHEMA_VERSION
    assert core_side.SOCKET_PATH == helper_side.SOCKET_PATH
    assert core_side.OBSERVATIONS == helper_side.OBSERVATIONS
    assert core_side.ALLOWED_KEYS == helper_side.ALLOWED_KEYS
    for name in ("MAX_LINE_BYTES", "MAX_PAYLOAD_KEYS", "MAX_STRING_CHARS",
                 "MAX_LIST_ITEMS"):
        assert getattr(core_side, name) == getattr(helper_side, name), name


def test_both_validators_reject_the_same_hostile_payloads():
    """So HÀNH VI, không chỉ so hằng số."""
    from packet_helper.protocol import clean_payload as helper_clean
    from shield.agent.collectors.packet_protocol import clean_payload as core_clean

    cases = [
        {"ip": "192.0.2.5", "mac": "AA:BB:CC:DD:EE:FF", "dst_port": 22},
        {"ip": "999.1.1.1"}, {"mac": "nope"}, {"dst_port": "22"},
        {"dst_port": -1}, {"interface": "x" * 500}, {"known": ["a"] * 100},
        {"ip": "192.0.2.5", "evil": "rm -rf /"}, {}, {"ip": {"a": 1}},
    ]
    for payload in cases:
        assert core_clean(payload) == helper_clean(payload), payload
