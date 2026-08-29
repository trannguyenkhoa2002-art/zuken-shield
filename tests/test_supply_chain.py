import hashlib
import json

from shield.agent.store import Store
from shield.security.supply_chain import verify_update_manifest


def test_update_manifest_hash_verification_and_tamper(tmp_path):
    artifact = tmp_path / "shield.whl"
    artifact.write_bytes(b"version-one")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": 1,
        "artifacts": {"shield.whl": hashlib.sha256(b"version-one").hexdigest()},
    }))
    assert verify_update_manifest(manifest, tmp_path)[0]
    artifact.write_bytes(b"tampered")
    ok, errors = verify_update_manifest(manifest, tmp_path)
    assert not ok and "hash mismatch" in errors[0]


def test_update_manifest_rejects_path_escape(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "artifacts": {"../outside": "0" * 64}}))
    assert not verify_update_manifest(manifest, tmp_path)[0]


def test_forensic_checkpoint_detects_tail_truncation(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_AUDIT_HMAC_KEY", "checkpoint-secret")
    store = Store(tmp_path / "db.sqlite")
    store.add_forensic_record("one", {"n": 1})
    store.add_forensic_record("two", {"n": 2})
    checkpoint_path = tmp_path / "checkpoint.json"
    store.create_forensic_checkpoint(checkpoint_path)
    assert store.verify_forensic_checkpoint(checkpoint_path)[0]
    store.conn.execute("DELETE FROM forensic_ledger WHERE id=2")
    store.conn.commit()
    ok, message = store.verify_forensic_checkpoint(checkpoint_path)
    assert not ok and ("truncated" in message or "diverged" in message)
    store.close()
