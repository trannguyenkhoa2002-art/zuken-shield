import json
import zipfile

from shield.agent.store import Store
from shield.security.diagnostics import export_diagnostic_bundle, sanitize


def test_recursive_sanitizer_redacts_secret_fields_and_inline_values():
    value = sanitize({
        "token": "abc", "nested": {"wifi_password": "secret", "detail": "token=visible"},
    })
    assert value["token"] == "<redacted>"
    assert value["nested"]["wifi_password"] == "<redacted>"
    assert "visible" not in value["nested"]["detail"]


def test_diagnostic_bundle_contains_only_sanitized_operational_data(tmp_path, monkeypatch):
    store = Store(tmp_path / "shield.db")
    monkeypatch.setenv("SHIELD_AUDIT_HMAC_KEY", "must-not-leak")
    output = tmp_path / "diagnostics.zip"
    manifest = export_diagnostic_bundle(store, output)
    assert output.stat().st_mode & 0o777 == 0o600
    with zipfile.ZipFile(output) as bundle:
        assert set(bundle.namelist()) == {"diagnostics.json", "manifest.json"}
        payload = bundle.read("diagnostics.json")
        parsed = json.loads(payload)
    assert b"must-not-leak" not in payload
    assert "database content" in manifest["excluded"]
    assert parsed["database"]["integrity_ok"] is True
    assert "collector_health" in parsed
    store.close()
