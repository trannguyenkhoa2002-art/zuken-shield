import asyncio
import json

import pytest

from shield.common.secrets import REDACTED
from shield.security.analysis import LocalSummaryAnalyzer, redact
from shield.security.plugins import PluginManifest, discover_plugins


def test_redaction_is_recursive_and_removes_bearer_tokens():
    clean = redact({
        "password": "secret", "nested": {"api_key": "key"},
        "message": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    })
    assert clean["password"] == REDACTED
    assert clean["nested"]["api_key"] == REDACTED
    assert "abcdefghijklmnopqrstuvwxyz" not in clean["message"]


def test_analyzer_redaction_catches_what_the_old_local_rules_missed():
    """Bộ luật cũ của module này bỏ lọt đúng những thứ dưới đây.

    Nó chỉ biết 5 tên khoá và một regex `bearer`. `LocalSummaryAnalyzer` thì
    chạy trên bản ghi THẬT, nên mỗi mục ở đây từng đi qua nguyên vẹn.
    """
    clean = redact({
        "aws": "AKIAIOSFODNN7EXAMPLE",
        "gh": "ghp_" + "a" * 36,
        "slack": "xoxb-123456789012-abcdefghijkl",
        "openai": "sk-" + "b" * 32,
        "pem": "-----BEGIN RSA PRIVATE KEY-----\nAAAA",
        "cmdline": "/usr/bin/curl --header API_KEY=hunter2 https://example.test",
        "cookie": "anything",
    })
    for field in ("aws", "gh", "slack", "openai", "pem"):
        assert clean[field] == REDACTED, field
    assert clean["cookie"] == REDACTED  # khớp theo TÊN khoá
    assert "hunter2" not in clean["cmdline"]
    assert "API_KEY" in clean["cmdline"]  # giữ tên trường, bỏ giá trị


def test_every_redaction_path_gives_the_same_answer():
    """Ba đường đọc, một câu trả lời.

    Hai bộ luật che cho cùng một khái niệm là hai câu trả lời khác nhau cho
    cùng một câu hỏi, và câu được dùng sẽ là câu nào tình cờ được import. Lỗi
    đó đã xảy ra hai lần trong repo này.
    """
    from shield.common.secrets import redact as canonical
    from shield.evidence.queries import redact as query_path

    payload = {
        "token": "abc",
        "note": "AKIAIOSFODNN7EXAMPLE",
        "nested": [{"password": "p"}, "sk-" + "c" * 32],
        "cmd": "run --password=hunter2",
        "harmless": "hello",
    }
    assert redact(payload) == canonical(payload) == query_path(payload)


def test_local_analyzer_is_offline_and_read_only_summary():
    async def scenario():
        result = await LocalSummaryAnalyzer().analyze([
            {"severity": "critical", "rule_id": "A", "subject": "host"},
            {"severity": "warning", "rule_id": "A", "subject": "host"},
        ])
        assert result.offline
        assert result.record_count == 2
        assert "1 critical" in result.summary
        assert result.engine == "local-summary-v1"
    asyncio.run(scenario())


def test_local_analyzer_supports_vietnamese():
    result = asyncio.run(LocalSummaryAnalyzer().analyze(
        [{"severity": "critical", "rule_id": "A", "subject": "máy"}], lang="vi"
    ))
    assert "Đã phân tích" in result.summary
    assert "phát hiện nguy cấp" in result.observations[0]


def write_plugin(tmp_path, manifest, with_entrypoint=True):
    directory = tmp_path / manifest.get("id", "plugin")
    directory.mkdir()
    (directory / "plugin.json").write_text(json.dumps(manifest))
    if with_entrypoint:
        (directory / manifest.get("entrypoint", "main.py")).write_text("print('{}')")
    return directory


def valid_manifest():
    return {
        "id": "example", "name": "Example", "version": "1.0.0",
        "api_version": 1, "entrypoint": "main.py",
        "permissions": ["read_alerts", "emit_annotation"],
    }


def test_plugin_manifest_accepts_read_only_permissions(tmp_path):
    directory = write_plugin(tmp_path, valid_manifest())
    manifest = PluginManifest.load(directory)
    assert manifest.api_version == 1
    assert "emit_annotation" in manifest.permissions


def test_plugin_manifest_rejects_response_permission(tmp_path):
    raw = valid_manifest()
    raw["permissions"] = ["block_ip"]
    directory = write_plugin(tmp_path, raw)
    with pytest.raises(ValueError, match="forbidden"):
        PluginManifest.load(directory)


def test_plugin_manifest_rejects_path_escape(tmp_path):
    raw = valid_manifest()
    raw["entrypoint"] = "../escape.py"
    directory = write_plugin(tmp_path, raw, with_entrypoint=False)
    with pytest.raises(ValueError, match="relative"):
        PluginManifest.load(directory)


def test_discovery_skips_invalid_and_missing_entrypoints(tmp_path):
    write_plugin(tmp_path, valid_manifest())
    missing = valid_manifest()
    missing["id"] = "missing"
    write_plugin(tmp_path, missing, with_entrypoint=False)
    found = discover_plugins(tmp_path)
    assert [manifest.id for _, manifest in found] == ["example"]
