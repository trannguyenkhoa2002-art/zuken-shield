from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shield.agent.store import Store
from shield.assessment.lab import evaluate_release_gate, lab_manifest
from shield.common.models import Alert, Event
from shield.security.anomaly import LocalBaselineDetector
from shield.security.fleet import FleetRegistry
from shield.security.investigations import InvestigationService, build_process_graph
from shield.security.intel import SignedOfflineFeedProvider, normalize_indicator, stix_bundle_entries
from shield.security.mitre import (
    BehaviorChainDetector, Suppression, SuppressionPolicy, attack_coverage, enrich_alert,
    import_sigma_subset,
)
from shield.security.plugins import discover_plugins
from shield.security.response import IsolationPlan, process_tree_identities
from shield.security.tamper import signed_snapshot, verify_snapshot
from shield.security.telemetry import KernelTelemetrySelector, normalize_kernel_record


def test_kernel_telemetry_falls_back_explicitly(tmp_path: Path):
    (tmp_path / "proc").mkdir()
    capability = KernelTelemetrySelector(tmp_path).detect()
    assert capability.backend == "procfs"
    assert capability.available and not capability.event_driven
    event = normalize_kernel_record({"ts": 1, "kind": "process_exec", "data": {"pid": "7"}}, "auditd")
    assert event.data == {"pid": 7, "telemetry_backend": "auditd"}


def test_mitre_enrichment_coverage_suppression_and_sigma_subset():
    alert = Alert(1, "LOCAL_SSH_BRUTEFORCE", "warning", "x", "y", "192.0.2.1")
    enriched = enrich_alert(alert)
    assert enriched.evidence["mitre_technique"] == "T1110.001"
    assert attack_coverage([enriched.to_dict()])["techniques_observed"] == ["T1110.001"]
    assert SuppressionPolicy([Suppression("LOCAL_*", "192.0.2.*", time.time() + 60, "lab")]).reason(alert) == "lab"
    rule = import_sigma_subset({
        "id": "test-rule", "title": "Test", "level": "high",
        "logsource": {"category": "process_exec"},
        "detection": {"selection": {"exe": "/tmp/x"}, "condition": "selection"},
    })
    assert rule.matches(Event(1, "kernel", "process_exec", {"exe": "/tmp/x"}))


def test_behavior_chain_is_ordered_and_bounded():
    detector = BehaviorChainDetector()
    base = {"pid": 42, "start_ticks": "10", "process_identity": "42:10"}
    assert detector.handle_event(Event(1, "kernel", "process_exec", base)) == []
    # Đường ghi là BẮT BUỘC từ 2.0: chuỗi chỉ kêu khi file rơi vào chỗ dropper
    # hay dùng. Không có nó thì mỗi lượt `apt upgrade` là một alert.
    assert detector.handle_event(
        Event(2, "kernel", "file_write", {**base, "path": "/tmp/payload"})) == []
    alerts = detector.handle_event(Event(3, "kernel", "socket_connect", base))
    assert alerts[0].rule_id == "BEHAVIOR_EXEC_WRITE_CONNECT"
    assert alerts[0].evidence["dropped_paths"] == ["/tmp/payload"]
    assert enrich_alert(alerts[0]).evidence["mitre_technique"] == "T1059"


def test_a_package_manager_writing_to_its_cache_is_not_a_chain():
    """`apt` ghi một gói rồi tải về khớp đúng hình dạng chuỗi tấn công.

    Trước 2.0 điều này không lộ ra vì collector chưa bao giờ phát `file_write`
    — chuỗi là code chết. Ngay khi telemetry chảy thật (mục 0.4), luật rộng như
    cũ kêu mỗi lần cập nhật gói. Corpus ground-truth bắt được nó.
    """
    detector = BehaviorChainDetector()
    base = {"pid": 1200, "start_ticks": "5", "process_identity": "1200:5"}
    detector.handle_event(Event(1, "kernel", "process_exec", {**base, "comm": "apt"}))
    detector.handle_event(Event(2, "kernel", "file_write",
                                {**base, "path": "/var/cache/apt/archives/x.deb"}))
    assert detector.handle_event(Event(3, "kernel", "socket_connect", base)) == []


def test_a_chain_without_a_known_write_path_stays_silent():
    """Không biết ghi vào đâu thì không kết luận. Đoán bừa còn tệ hơn im lặng."""
    detector = BehaviorChainDetector()
    base = {"pid": 7, "start_ticks": "1", "process_identity": "7:1"}
    detector.handle_event(Event(1, "kernel", "process_exec", base))
    detector.handle_event(Event(2, "kernel", "file_write", base))
    assert detector.handle_event(Event(3, "kernel", "socket_connect", base)) == []


def test_an_uncalibrated_chain_does_not_shout_critical():
    """Một detector chưa hiệu chuẩn mà kêu mức nguy cấp sẽ dạy người dùng bỏ
    qua mức nguy cấp."""
    detector = BehaviorChainDetector()
    base = {"pid": 8, "start_ticks": "1", "process_identity": "8:1"}
    detector.handle_event(Event(1, "kernel", "process_exec", base))
    detector.handle_event(Event(2, "kernel", "file_write", {**base, "path": "/tmp/x"}))
    alert = detector.handle_event(Event(3, "kernel", "socket_connect", base))[0]
    assert alert.severity == "warning"


def test_local_baseline_learns_then_flags_first_seen(tmp_path: Path):
    store = Store(tmp_path / "baseline.db")
    try:
        detector = LocalBaselineDetector(store, learning_days=1)
        learned = Event(time.time(), "kernel", "process_exec", {"uid": 1000, "exe": "/usr/bin/known"})
        assert detector.handle_event(learned) == []
        store.set_baseline("anomaly_learning_started", str(time.time() - 2 * 86400))
        novel = Event(time.time(), "kernel", "process_exec", {"uid": 1000, "exe": "/opt/new"})
        assert detector.handle_event(novel)[0].rule_id == "ANOMALY_NEW_BEHAVIOR"
        synthetic = Event(time.time(), "assessment", "process_exec", {"synthetic": True, "exe": "/tmp/x"})
        assert detector.handle_event(synthetic) == []
    finally:
        store.close()


def test_investigation_cases_search_and_process_graph(tmp_path: Path):
    store = Store(tmp_path / "cases.db")
    try:
        service = InvestigationService(store)
        case = service.create_case("Suspicious process", "42:10", ["RULE_A"])
        service.add_note(case["case_id"], "analyst", "Validated evidence")
        service.set_state(case["case_id"], "investigating")
        assert store.list_cases()[0]["state"] == "investigating"
        assert store.case_notes(case["case_id"])[0]["note"] == "Validated evidence"
        store.insert_event(Event(time.time(), "kernel", "process_exec", {"pid": 42, "ppid": 7, "start_ticks": "10", "exe": "/opt/x"}))
        records = store.search_security_records("/opt/x")
        assert records[0]["record_type"] == "event"
        graph = build_process_graph(records)
        assert graph["nodes"][0]["pid"] == 42 and graph["edges"]
    finally:
        store.close()


def _fake_stat(proc: Path, pid: int, ppid: int, ticks: str) -> None:
    path = proc / str(pid); path.mkdir(parents=True)
    fields = ["S", str(ppid)] + ["0"] * 17 + [ticks] + ["0"] * 4
    (path / "stat").write_text(f"{pid} (worker) " + " ".join(fields))


def test_process_tree_identity_and_isolation_safety(tmp_path: Path):
    proc = tmp_path / "proc"; proc.mkdir()
    _fake_stat(proc, 42, 1, "100")
    _fake_stat(proc, 43, 42, "101")
    _fake_stat(proc, 44, 43, "102")
    identities = process_tree_identities(42, "100", proc)
    assert [item["pid"] for item in identities] == [44, 43, 42]
    assert IsolationPlan.create("192.0.2.10", 60).preview().ok
    with pytest.raises(ValueError):
        IsolationPlan.create("224.0.0.1", 60)


def test_offline_intel_url_and_stix(tmp_path: Path):
    assert normalize_indicator("HTTPS://Example.COM/path#fragment") == ("url", "https://example.com/path")
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"schema_version": 1, "indicators": [{"value": "example.org", "verdict": "malicious"}]}))
    provider = SignedOfflineFeedProvider.load(feed)
    assert provider.entries[("domain", "example.org")] == "malicious"
    entries = stix_bundle_entries({"type": "bundle", "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '192.0.2.4']"}]})
    assert entries[("ip", "192.0.2.4")] == "malicious"


def test_tamper_snapshot_detects_change_and_authenticates(tmp_path: Path):
    root = tmp_path / "app"; root.mkdir()
    target = root / "module.py"; target.write_text("safe")
    snapshot = signed_snapshot(root, b"key")
    assert verify_snapshot(snapshot, root, b"key") == (True, [])
    target.write_text("changed")
    valid, changed = verify_snapshot(snapshot, root, b"key")
    assert not valid and changed == ["module.py"]
    assert not verify_snapshot(snapshot, root, b"wrong")[0]


def test_fleet_uses_certificates_rbac_and_has_no_shell_command(tmp_path: Path):
    store = Store(tmp_path / "fleet.db")
    try:
        registry = FleetRegistry(store)
        endpoint = registry.enroll("lab-01", b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----", "analyst")
        assert registry.authorize(endpoint.certificate_fingerprint, "request_health")
        assert registry.authorize(endpoint.certificate_fingerprint, "request_assessment")
        assert not registry.authorize(endpoint.certificate_fingerprint, "push_signed_rules")
        assert not registry.authorize(endpoint.certificate_fingerprint, "shell")
    finally:
        store.close()


def test_plugin_signed_mode_fails_closed_without_key(tmp_path: Path):
    plugin = tmp_path / "p"; plugin.mkdir()
    (plugin / "plugin.json").write_text(json.dumps({"id": "p", "name": "p", "version": "1", "api_version": 1, "entrypoint": "main.py", "permissions": []}))
    (plugin / "main.py").write_text("print('{}')")
    assert discover_plugins(tmp_path)
    assert discover_plugins(tmp_path, require_signed=True) == []


def test_release_gate_refuses_missing_or_failed_isolated_tests():
    manifest = lab_manifest()
    assert len(manifest) == 5
    assert not evaluate_release_gate([])["passed"]
    failed = [{"id": item["id"], "status": "passed"} for item in manifest]
    failed[0]["status"] = "failed"
    assert not evaluate_release_gate(failed)["passed"]
    assert evaluate_release_gate([{**item, "status": "passed"} for item in manifest])["passed"]
