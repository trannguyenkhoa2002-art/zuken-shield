from pathlib import Path

from shield.agent.collectors.endpoint import fim_snapshot, network_snapshot, process_snapshot, snapshot_changes, usb_snapshot
from shield.agent.detectors.endpoint import EndpointDetector
from shield.common.models import Event


def test_snapshot_changes_reports_all_categories():
    old = {"a": {"value": 1}, "b": {"value": 2}}
    new = {"b": {"value": 3}, "c": {"value": 4}}
    added, removed, changed = snapshot_changes(old, new)
    assert added == [{"value": 4}]
    assert removed == [{"value": 1}]
    assert changed == [{"before": {"value": 2}, "after": {"value": 3}}]


def test_fim_hash_and_change(tmp_path: Path):
    target = tmp_path / "important.conf"
    target.write_text("version=1")
    first = fim_snapshot([target])
    target.write_text("version=2")
    second = fim_snapshot([target])
    _, _, changed = snapshot_changes(first, second)
    assert len(changed) == 1
    assert changed[0]["before"]["sha256"] != changed[0]["after"]["sha256"]
    assert changed[0]["after"]["path"] == str(target)


def test_process_snapshot_from_fake_proc(tmp_path: Path):
    proc = tmp_path / "proc"
    pid = proc / "42"
    pid.mkdir(parents=True)
    # comm may contain spaces; parser finds the final ')' like procfs readers should.
    fields = ["S"] + ["0"] * 18 + ["12345"] + ["0"] * 5
    (pid / "stat").write_text("42 (worker process) " + " ".join(fields))
    (pid / "cmdline").write_bytes(b"/usr/bin/worker\0--safe\0")
    (pid / "exe").symlink_to("/usr/bin/worker")
    snap = process_snapshot(proc)
    assert snap[42]["start_ticks"] == "12345"
    assert snap[42]["cmdline"] == "/usr/bin/worker --safe"


def test_usb_snapshot_reads_identity(tmp_path: Path):
    dev = tmp_path / "1-2"
    dev.mkdir()
    (dev / "idVendor").write_text("abcd")
    (dev / "idProduct").write_text("1234")
    (dev / "product").write_text("Test key")
    snap = usb_snapshot(tmp_path)
    assert snap["1-2"]["product"] == "Test key"


def test_network_snapshot_keeps_listeners_only(tmp_path: Path):
    (tmp_path / "tcp").write_text(
        "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        "   0: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 1000 0 12345\n"
        "   1: 0100007F:C001 0100007F:01BB 01 0:0 0:0 0 1000 0 12346\n"
    )
    snap = network_snapshot(tmp_path)
    assert list(snap.values())[0]["ip"] == "127.0.0.1"
    assert list(snap.values())[0]["port"] == 22
    assert len(snap) == 1


def test_suspicious_temporary_process_alert():
    alerts = EndpointDetector().handle_event(Event(
        1.0, "endpoint", "process_started",
        {"pid": 9, "exe": "/dev/shm/payload", "cmdline": "/dev/shm/payload"},
    ))
    assert alerts[0].rule_id == "ENDPOINT_SUSPICIOUS_EXEC_PATH"


def test_normal_process_does_not_alert():
    alerts = EndpointDetector().handle_event(Event(
        1.0, "endpoint", "process_started",
        {"pid": 1, "exe": "/usr/lib/systemd/systemd", "cmdline": "/sbin/init"},
    ))
    assert alerts == []


def test_sensitive_listener_alerts():
    alerts = EndpointDetector().handle_event(Event(
        1.0, "endpoint", "listener_opened",
        {"protocol": "tcp4", "ip": "0.0.0.0", "port": 445, "inode": "7"},
    ))
    assert alerts[0].rule_id == "ENDPOINT_SENSITIVE_LISTENER_OPENED"
