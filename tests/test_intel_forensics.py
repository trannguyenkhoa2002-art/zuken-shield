import asyncio

import pytest

from shield.agent.store import Store
from shield.security.intel import StaticIntelProvider, ThreatIntelService, normalize_indicator


def test_indicator_normalization():
    assert normalize_indicator("2001:0db8::1") == ("ip", "2001:db8::1")
    assert normalize_indicator("Example.COM.") == ("domain", "example.com")
    assert normalize_indicator("A" * 64) == ("hash", "a" * 64)
    with pytest.raises(ValueError):
        normalize_indicator("not an indicator")


def test_static_intel_and_cache(tmp_path):
    async def scenario():
        store = Store(tmp_path / "db.sqlite")
        provider = StaticIntelProvider({("ip", "192.0.2.9"): "malicious"})
        service = ThreatIntelService(store, [provider])
        first = await service.check("192.0.2.9")
        assert first[0].verdict == "malicious" and not first[0].cached
        provider.entries.clear()
        second = await service.check("192.0.2.9")
        assert second[0].verdict == "malicious" and second[0].cached
        store.close()
    asyncio.run(scenario())


def test_forensic_ledger_verifies_and_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AUDIT_HMAC_KEY", "test-secret")
    store = Store(tmp_path / "db.sqlite")
    store.add_audit_log("one", {"target": "x"}, "OK")
    store.add_forensic_record("alert", {"rule_id": "TEST"})
    assert store.verify_forensic_ledger()[0]
    store.conn.execute("UPDATE forensic_ledger SET payload='{}' WHERE id=1")
    store.conn.commit()
    ok, bad_id, reason = store.verify_forensic_ledger()
    assert not ok and bad_id == 1 and "mismatch" in reason
    store.close()


def test_forensic_hmac_rejects_recomputed_unkeyed_entry(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AUDIT_HMAC_KEY", "test-secret")
    store = Store(tmp_path / "db.sqlite")
    store.add_forensic_record("test", {"value": 1})
    store.conn.execute("UPDATE forensic_ledger SET auth_tag='' WHERE id=1")
    store.conn.commit()
    assert store.verify_forensic_ledger()[2] == "HMAC mismatch"
    store.close()
