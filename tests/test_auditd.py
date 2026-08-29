from shield.agent.collectors.auditd import parse_audit_message
from shield.agent.detectors.endpoint import EndpointDetector


def test_parse_execve_syscall_event():
    event = parse_audit_message(
        'type=SYSCALL msg=audit(1.2:3): arch=c000003e syscall=59 success=yes ppid=10 pid=11 '
        'auid=1000 uid=1000 comm="payload" exe="/tmp/payload" key="shield_exec"'
    )
    assert event.kind == "process_exec"
    assert event.data["pid"] == 11
    assert event.data["exe"] == "/tmp/payload"
    assert EndpointDetector().handle_event(event)[0].rule_id == "ENDPOINT_SUSPICIOUS_EXEC_PATH"


def test_parse_protected_file_watch():
    event = parse_audit_message(
        'type=PATH msg=audit(1.2:4): name="/etc/sudoers" pid=22 uid=0 '
        'exe="/usr/bin/editor" key="shield_sudoers"'
    )
    assert event.kind == "security_file_changed"
    alert = EndpointDetector().handle_event(event)[0]
    assert alert.severity == "critical"


def test_ignore_unrelated_audit_message():
    assert parse_audit_message('type=LOGIN pid=1 uid=0') is None
