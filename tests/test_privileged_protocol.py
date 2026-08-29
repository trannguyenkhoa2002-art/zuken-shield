import pytest

from shield.privileged.protocol import PrivilegedRequest


def request(action, params):
    return {"request_id": "abc", "action": action, "params": params}


def test_protocol_normalizes_exact_ip_request():
    parsed = PrivilegedRequest.parse(request("block_ip", {"ip": "192.0.2.1"}))
    assert parsed.params == {"ip": "192.0.2.1"}


@pytest.mark.parametrize("raw", [
    request("shell", {"cmd": "rm"}),
    request("block_ip", {"ip": "192.0.2.1", "extra": True}),
    request("block_ip", {"ip": "not-ip"}),
    request("block_mac", {"mac": "bad"}),
    request("stop_process", {"pid": 1, "start_ticks": "2"}),
])
def test_protocol_rejects_broad_or_malformed_requests(raw):
    with pytest.raises(ValueError):
        PrivilegedRequest.parse(raw)


def test_stop_process_requires_pid_and_start_ticks_only():
    parsed = PrivilegedRequest.parse(request("stop_process", {"pid": 42, "start_ticks": "123"}))
    assert parsed.params == {"pid": 42, "start_ticks": "123"}
