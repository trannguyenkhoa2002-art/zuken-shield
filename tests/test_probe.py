"""Shield Probe — agent nhỏ đọc log trên máy khác (kế hoạch 1.1 mục A1).

Không mở socket, không chạy journalctl thật, không chạm mạng: spool và reader
là logic thuần, còn `normalize_record` phía server nhận thẳng dict.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path
from pathlib import Path as _Path

import pytest

from probe.config import ProbeConfig
from probe.reader import FileLogReader, JournalReader, ReaderState, classify, journal_record_to_event
from probe.spool import Spool
from shield.agent.collectors.log_ingest import (
    ALLOWED_KINDS,
    ProbeRateLimiter,
    normalize_record,
)
from shield.security.fleet import FLEET_ROLES, FleetRegistry
from shield.security.trust import AUTHENTICATED

ROOT = Path(__file__).resolve().parent.parent


# --- probe phải nhẹ ---


def test_the_probe_package_never_imports_the_heavy_desktop_stack():
    """Probe cài lên máy KHÔNG có PySide6/scapy. Nếu lỡ import, gói .deb nhẹ
    trở thành lời hứa suông và probe sẽ chết ngay lúc khởi động."""
    banned = {"PySide6", "PyQt6", "scapy", "pyqtgraph", "reportlab", "manuf", "shield"}
    for path in (ROOT / "probe").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            leaked = banned.intersection(names)
            assert not leaked, f"{path.name} import {leaked} — probe phải chỉ dùng stdlib"


def test_the_probe_never_ships_an_action_capability():
    """Probe CHỈ ĐỌC. Một probe bị chiếm quyền không được trở thành vũ khí.

    Kiểm bằng AST chứ không grep văn bản: nếu grep, một dòng chú thích nói
    "probe không đụng vào nftables" cũng làm test đỏ, và người sửa sẽ học
    cách né test thay vì giữ ranh giới.
    """
    # chmod KHÔNG nằm trong danh sách: probe tự đặt 0600 cho config, spool và
    # khoá riêng của chính nó — đó là vệ sinh quyền file, không phải hành động
    # lên hệ thống.
    forbidden_calls = {"kill", "killpg", "setuid", "seteuid", "system", "chown", "remove", "rmtree"}
    allowed_binaries = {"/usr/bin/journalctl"}

    for path in (ROOT / "probe").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_calls, (
                    f"{path.name} gọi {node.func.attr}() — probe không được hành động"
                )
            # Mọi tiến trình con probe chạy đều phải nằm trong allowlist.
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith("/usr/") or node.value.startswith("/sbin/"):
                    assert node.value in allowed_binaries, (
                        f"{path.name} tham chiếu binary {node.value!r} ngoài allowlist"
                    )


# --- spool ---


def test_spool_round_trips_records(tmp_path):
    spool = Spool(tmp_path / "spool", max_bytes=10 * 1024 * 1024)
    for i in range(10):
        spool.append({"ts": i, "source": "probe", "kind": "log_line", "data": {"i": i}})
    records, _bytes = spool.read_batch(100, 1024 * 1024)
    assert len(records) == 10
    assert [r["data"]["i"] for r in records] == list(range(10))


def test_reading_does_not_remove_anything_until_the_server_confirms(tmp_path):
    """Xoá lúc đọc nghĩa là mạng đứt giữa chừng thì mất hẳn dòng đó. Thà gửi
    trùng còn hơn mất."""
    spool = Spool(tmp_path / "spool", max_bytes=10 * 1024 * 1024)
    for i in range(5):
        spool.append({"ts": i, "source": "probe", "kind": "log_line", "data": {}})
    spool.read_batch(5, 1024 * 1024)
    assert spool.pending_lines() == 5
    spool.commit(5)
    assert spool.pending_lines() == 0


def test_a_partial_commit_only_removes_what_the_server_accepted(tmp_path):
    spool = Spool(tmp_path / "spool", max_bytes=10 * 1024 * 1024)
    for i in range(10):
        spool.append({"ts": i, "source": "probe", "kind": "log_line", "data": {"i": i}})
    spool.commit(4)
    records, _ = spool.read_batch(100, 1024 * 1024)
    assert [r["data"]["i"] for r in records] == list(range(4, 10))


def test_a_full_spool_drops_the_oldest_and_says_so(tmp_path):
    """Im lặng mất log là điều tệ nhất một hệ thống bằng chứng có thể làm."""
    spool = Spool(tmp_path / "spool", max_bytes=8192, segment_bytes=2048)
    for i in range(2000):
        spool.append({"ts": i, "source": "probe", "kind": "log_line",
                      "data": {"message": "x" * 100, "i": i}})
    assert spool.size_bytes() <= 8192 * 2
    assert spool.dropped > 0
    records, _ = spool.read_batch(5000, 10 * 1024 * 1024)
    kinds = {r["kind"] for r in records}
    assert "probe_spool_overflow" in kinds, "spool tràn mà không để lại dấu vết"
    # Dòng còn lại phải là dòng MỚI nhất, không phải cũ nhất.
    indices = [r["data"].get("i") for r in records if r["kind"] == "log_line"]
    assert max(indices) == 1999


def test_a_truncated_line_from_a_power_cut_does_not_poison_the_whole_spool(tmp_path):
    spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
    spool.append({"ts": 1, "source": "probe", "kind": "log_line", "data": {"ok": True}})
    segment = spool.segments()[0]
    with segment.open("a", encoding="utf-8") as handle:
        handle.write('{"ts": 2, "source": "probe", "kind": "log_l')
    records, _ = spool.read_batch(10, 1024 * 1024)
    assert len(records) == 1 and records[0]["data"]["ok"] is True


# --- reader: không mất dòng, không gửi trùng ---


def test_a_file_reader_only_returns_new_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("dòng 1\ndòng 2\n", encoding="utf-8")
    state = ReaderState(tmp_path / "state.json")
    reader = FileLogReader(log, state)

    assert reader.read_new_lines() == ["dòng 1", "dòng 2"]
    reader.commit()
    assert reader.read_new_lines() == []

    with log.open("a", encoding="utf-8") as handle:
        handle.write("dòng 3\n")
    assert reader.read_new_lines() == ["dòng 3"]


def test_the_cursor_survives_a_restart(tmp_path):
    """Mất dòng sau mỗi lần restart là cách âm thầm nhất để mất bằng chứng."""
    log = tmp_path / "auth.log"
    log.write_text("a\nb\n", encoding="utf-8")
    state_file = tmp_path / "state.json"

    reader = FileLogReader(log, ReaderState(state_file))
    reader.read_new_lines()
    reader.commit()

    # Tiến trình mới, state đọc lại từ đĩa.
    restarted = FileLogReader(log, ReaderState(state_file))
    assert restarted.read_new_lines() == []
    with log.open("a", encoding="utf-8") as handle:
        handle.write("c\n")
    assert restarted.read_new_lines() == ["c"]


def test_logrotate_does_not_lose_or_duplicate_lines(tmp_path):
    """Chỉ nhớ offset thì sau logrotate probe hoặc nhảy vào giữa file mới,
    hoặc đọc lại từ đầu — cả hai đều sai."""
    log = tmp_path / "auth.log"
    log.write_text("cũ 1\ncũ 2\ncũ 3\n", encoding="utf-8")
    state = ReaderState(tmp_path / "state.json")
    reader = FileLogReader(log, state)
    reader.read_new_lines()
    reader.commit()

    log.rename(tmp_path / "auth.log.1")          # logrotate
    log.write_text("mới 1\n", encoding="utf-8")   # file mới, inode khác
    assert reader.read_new_lines() == ["mới 1"]


def test_copytruncate_rotation_is_handled(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("a\nb\nc\n", encoding="utf-8")
    reader = FileLogReader(log, ReaderState(tmp_path / "state.json"))
    reader.read_new_lines()
    reader.commit()
    log.write_text("mới\n", encoding="utf-8")  # cắt tại chỗ, giữ inode
    assert reader.read_new_lines() == ["mới"]


def test_a_line_still_being_written_is_left_for_the_next_pass(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("trọn vẹn\nđang ghi dở", encoding="utf-8")
    reader = FileLogReader(log, ReaderState(tmp_path / "state.json"))
    assert reader.read_new_lines() == ["trọn vẹn"]


def test_journal_command_uses_a_cursor_file(tmp_path):
    reader = JournalReader(tmp_path, ["sshd", "sudo"])
    command = reader.command(100)
    assert any(arg.startswith("--cursor-file=") for arg in command)
    assert command.count("--identifier") == 2


# --- phân loại ---


@pytest.mark.parametrize("message,expected", [
    ("Failed password for invalid user root from 10.0.0.5 port 22", "ssh_auth_failure"),
    ("Accepted publickey for admin from 10.0.0.5 port 22", "ssh_auth_success"),
    ("pam_unix(sudo:auth): authentication failure; logname=x", "sudo_failure"),
    ("usb 1-2: New USB device found, idVendor=0781, idProduct=5583", "usb_device_added"),
    ("một dòng log bình thường", "log_line"),
])
def test_classification_matches_the_local_detectors(message, expected):
    kind, _fields = classify(message, "sshd")
    assert kind == expected


def test_journal_records_become_shield_events():
    event = journal_record_to_event(
        {"MESSAGE": "Failed password for root from 10.0.0.5 port 22",
         "SYSLOG_IDENTIFIER": "sshd", "__REALTIME_TIMESTAMP": "1700000000000000",
         "_SYSTEMD_UNIT": "ssh.service", "_PID": "42"},
        "probe-1", "may-ban",
    )
    assert event["kind"] == "ssh_auth_failure"
    assert event["data"]["ip"] == "10.0.0.5"
    assert event["data"]["probe_host"] == "may-ban"


# --- server: chuẩn hoá và kiểm tra đầu vào ---


def test_a_valid_record_becomes_an_authenticated_event():
    event = normalize_record(
        {"ts": time.time(), "source": "probe.journal", "kind": "ssh_auth_failure",
         "data": {"user": "root", "ip": "10.0.0.5"}},
        "probe-1", "10.0.0.9",
    )
    assert event is not None
    assert event.data["trust"] == AUTHENTICATED
    assert event.data["origin"] == "probe:probe-1"


def test_a_probe_cannot_claim_to_be_a_local_collector():
    """origin/trust do SERVER gắn. Nếu lấy từ payload, probe tự khai được
    mình là "local" và vượt qua mọi ranh giới tin cậy."""
    event = normalize_record(
        {"ts": time.time(), "source": "probe.journal", "kind": "log_line",
         "data": {"origin": "local", "trust": "authenticated", "probe_id": "tôi-là-agent"}},
        "probe-1", "10.0.0.9",
    )
    assert event.data["origin"] == "probe:probe-1"
    assert event.data["probe_id"] == "probe-1"


def test_a_probe_cannot_invent_arbitrary_event_kinds():
    """Allowlist chứ không phải blocklist: probe bị chiếm không được tự chọn
    kind để kích hoạt detector tuỳ ý."""
    assert normalize_record(
        {"ts": time.time(), "source": "probe.journal", "kind": "gateway_mac_changed", "data": {}},
        "probe-1", "10.0.0.9",
    ) is None
    assert "gateway_mac_changed" not in ALLOWED_KINDS


def test_a_probe_cannot_backdate_or_postdate_events():
    """Cho phép tự khai thời gian nghĩa là cho phép đẩy sự kiện lên đầu mọi
    timeline điều tra."""
    future = normalize_record(
        {"ts": time.time() + 86400 * 30, "source": "probe.journal", "kind": "log_line", "data": {}},
        "probe-1", "10.0.0.9",
    )
    assert future.ts <= time.time() + 300


@pytest.mark.parametrize("record", [
    None, [], "chuỗi", {}, {"source": "probe.journal"},
    {"ts": "không phải số", "source": "probe.journal", "kind": "log_line", "data": {}},
    {"ts": 1.0, "source": "kẻ-giả-mạo", "kind": "log_line", "data": {}},
    {"ts": 1.0, "source": "probe.journal", "kind": "log_line", "data": "không phải dict"},
])
def test_malformed_records_are_rejected(record):
    assert normalize_record(record, "probe-1", "10.0.0.9") is None


def test_oversized_fields_are_truncated():
    event = normalize_record(
        {"ts": time.time(), "source": "probe.journal", "kind": "log_line",
         "data": {"message": "x" * 100_000, **{f"k{i}": i for i in range(200)}}},
        "probe-1", "10.0.0.9",
    )
    assert len(event.data["message"]) <= 2000
    assert len(event.data) <= 45


def test_the_rate_limiter_caps_a_single_probe():
    limiter = ProbeRateLimiter(rate_per_s=100)
    assert limiter.take("probe-1", 500, at=100.0) == 100
    assert limiter.take("probe-1", 500, at=100.0) == 0
    assert limiter.take("probe-1", 500, at=101.0) == 100


# --- vai trò probe ---


def test_the_probe_role_exists_and_can_run_no_commands(tmp_path):
    """Probe chỉ gửi log LÊN. Cho nó chạy được lệnh nào cũng là mở một kênh
    điều khiển từ xa tới mọi máy trong LAN."""
    from shield.agent.store import Store

    assert "probe" in FLEET_ROLES
    store = Store(tmp_path / "shield.db")
    try:
        registry = FleetRegistry(store)
        identity = registry.enroll_fingerprint("may-ban", "a" * 64, "probe")
        assert identity.role == "probe"
        for command in ("request_health", "request_assessment", "push_signed_rules", "push_signed_config"):
            assert registry.authorize(identity.certificate_fingerprint, command) is False
    finally:
        store.close()


def test_enrolling_rejects_a_malformed_fingerprint(tmp_path):
    from shield.agent.store import Store

    store = Store(tmp_path / "shield.db")
    try:
        registry = FleetRegistry(store)
        for bad in ("", "xyz", "a" * 63, "g" * 64):
            with pytest.raises(ValueError):
                registry.enroll_fingerprint("may-ban", bad, "probe")
    finally:
        store.close()


def test_revoking_a_probe_removes_its_way_in(tmp_path):
    from shield.agent.store import Store

    store = Store(tmp_path / "shield.db")
    try:
        identity = FleetRegistry(store).enroll_fingerprint("may-ban", "b" * 64, "probe")
        assert store.get_endpoint_by_fingerprint("b" * 64) is not None
        assert store.revoke_endpoint(identity.endpoint_id) is True
        assert store.get_endpoint_by_fingerprint("b" * 64) is None
    finally:
        store.close()


# --- cấu hình ---


def test_config_validation_names_what_is_missing():
    with pytest.raises(ValueError) as excinfo:
        ProbeConfig().validate()
    assert "server_host" in str(excinfo.value)


def test_config_clamps_hostile_values():
    config = ProbeConfig.from_dict({
        "batch_lines": 10 ** 9, "batch_bytes": 10 ** 9,
        "rate_per_s": -5, "spool_max_bytes": 1,
    })
    assert config.batch_lines <= 5000
    assert config.batch_bytes <= 4 * 1024 * 1024
    assert config.rate_per_s >= 1
    assert config.spool_max_bytes >= 1024 * 1024


def test_config_ignores_unknown_keys_instead_of_crashing():
    config = ProbeConfig.from_dict({"server_host": "10.0.0.1", "khoá_lạ": "giá trị"})
    assert config.server_host == "10.0.0.1"


# --- audit ---


def test_audit_and_journal_use_separate_cursors():
    """Dùng chung con trỏ thì hai luồng nuốt mất bản ghi của nhau — và mất
    log kiểu đó im lặng tuyệt đối, không ai phát hiện được."""
    from probe.reader import JournalReader

    reader = JournalReader(_Path("/tmp/probe-state"), ["sshd"])
    journal_cursor = next(a for a in reader.command(10) if a.startswith("--cursor-file="))
    audit_cursor = next(a for a in reader.audit_command(10) if a.startswith("--cursor-file="))
    assert journal_cursor != audit_cursor
    # Audit không lọc theo --identifier được: nó tới qua _TRANSPORT=audit.
    assert "_TRANSPORT=audit" in reader.audit_command(10)
    assert "--identifier" not in reader.audit_command(10)


def test_audit_execve_becomes_a_process_event():
    from probe.reader import audit_record_to_event

    event = audit_record_to_event({
        "MESSAGE": 'arch=c000003e syscall=59 success=yes exe="/usr/bin/curl" comm="curl" uid=1000 auid=1000',
        "_AUDIT_TYPE_NAME": "SYSCALL", "__REALTIME_TIMESTAMP": "1700000000000000",
    }, "probe-1", "may-ban")
    assert event["source"] == "probe.audit"
    assert event["kind"] == "process_exec"
    assert event["data"]["exe"] == "/usr/bin/curl"


def test_audit_login_results_map_to_success_and_failure():
    from probe.reader import audit_record_to_event

    ok = audit_record_to_event({
        "MESSAGE": 'acct="khoa" addr=10.0.0.5 res=success', "_AUDIT_TYPE_NAME": "USER_AUTH",
    }, "p", "h")
    bad = audit_record_to_event({
        "MESSAGE": 'acct="root" addr=10.0.0.5 res=failed', "_AUDIT_TYPE_NAME": "USER_AUTH",
    }, "p", "h")
    assert ok["kind"] == "ssh_auth_success" and ok["data"]["user"] == "khoa"
    assert bad["kind"] == "ssh_auth_failure"


def test_uninteresting_audit_records_are_dropped_at_the_probe():
    """Audit trên máy bận sinh hàng nghìn dòng mỗi giây. Gửi hết về là làm
    nghẹt event bus của Shield mà không thêm thông tin gì."""
    from probe.reader import audit_record_to_event

    for audit_type in ("PATH", "CWD", "PROCTITLE", "SOCKADDR", ""):
        assert audit_record_to_event(
            {"MESSAGE": "x=1", "_AUDIT_TYPE_NAME": audit_type}, "p", "h"
        ) is None
    # syscall khác execve cũng bỏ
    assert audit_record_to_event(
        {"MESSAGE": "syscall=2 exe=\"/bin/cat\"", "_AUDIT_TYPE_NAME": "SYSCALL"}, "p", "h"
    ) is None


def test_every_allowed_ingest_source_has_something_that_produces_it():
    """Một mục thừa trong allowlist của server là một đường vào không ai kiểm."""
    from shield.agent.collectors.log_ingest import ALLOWED_SOURCES

    produced = set()
    reader_src = (ROOT / "probe" / "reader.py").read_text(encoding="utf-8")
    for source in ALLOWED_SOURCES:
        if f'"{source}"' in reader_src:
            produced.add(source)
    produced.add("probe")  # dùng cho `shield-probe test` và bản ghi tự tố cáo
    assert ALLOWED_SOURCES == produced, f"allowlist thừa: {sorted(ALLOWED_SOURCES - produced)}"


def test_audit_can_be_turned_off_for_machines_without_auditd():
    from probe.reader import JournalReader

    reader = JournalReader(_Path("/tmp/probe-state"), ["sshd"], include_audit=False)
    assert reader.read_new_audit_records() == []


def test_an_empty_identifier_list_reads_nothing(tmp_path):
    """Rỗng = không đọc journal, KHÔNG phải đọc tất cả.

    `journalctl` không có --identifier nào sẽ trả về toàn bộ journal của máy.
    Hiểu nhầm chiều này một lần là gửi nguyên nhật ký của một máy đi nơi khác
    mà chủ máy không hề chọn điều đó.
    """
    from probe.reader import JournalReader

    reader = JournalReader(tmp_path, [], include_audit=False)
    assert reader.read_new_records() == []
    # Và lệnh dựng ra cũng không được phép là một lệnh "lấy tất cả".
    assert "--identifier" not in reader.command(10) or reader.identifiers


def test_identifiers_are_still_read_normally(tmp_path, monkeypatch):
    from probe.reader import JournalReader

    reader = JournalReader(tmp_path, ["sshd"], include_audit=False)
    called = {}

    def fake_run(command, timeout):
        called["command"] = command
        return [{"MESSAGE": "x"}]

    monkeypatch.setattr(reader, "_run", fake_run)
    assert reader.read_new_records() == [{"MESSAGE": "x"}]
    assert "--identifier" in called["command"] and "sshd" in called["command"]
