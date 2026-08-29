from shield.common.models import Alert, Event, now


def test_event_roundtrip():
    ev = Event(ts=now(), source="test", kind="ping", data={"ip": "1.2.3.4"})
    d = ev.to_dict()
    ev2 = Event.from_dict(d)
    assert ev2 == ev


def test_alert_roundtrip():
    alert = Alert(
        ts=now(),
        rule_id="TEST_RULE",
        severity="warning",
        title="Test",
        detail="chi tiết",
        subject="1.2.3.4",
        evidence={"k": "v"},
        playbook=["block_ip"],
    )
    d = alert.to_dict()
    alert2 = Alert.from_dict(d)
    assert alert2 == alert
