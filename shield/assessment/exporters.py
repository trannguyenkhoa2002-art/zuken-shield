from __future__ import annotations

import hashlib
import hmac
import json
import time
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring


def export_junit(result: dict, path: Path) -> None:
    tests = result["results"]
    suite = Element("testsuite", name=result["profile_id"], tests=str(len(tests)), failures=str(sum(t["status"] == "failed" for t in tests)), skipped=str(sum(t["status"] == "skipped" for t in tests)))
    for test in tests:
        case = SubElement(suite, "testcase", name=test["test_id"], time=f"{test['finished_ts'] - test['started_ts']:.6f}")
        if test["status"] == "failed": SubElement(case, "failure", message="assessment assertions failed").text = json.dumps(test["assertions"])
        elif test["status"] in {"skipped", "inconclusive"}: SubElement(case, "skipped", message=test.get("error") or test["status"])
    path.write_bytes(b'<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(suite))


def export_sarif(result: dict, path: Path) -> None:
    entries = []
    for test in result["results"]:
        if test["status"] != "passed":
            entries.append({"ruleId": test["test_id"], "level": "error" if test["status"] == "failed" else "warning", "message": {"text": test.get("error") or "Assessment did not pass"}})
    payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Shield Assessment", "rules": []}}, "results": entries}]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_evidence_bundle(result: dict, path: Path, key: bytes = b"") -> dict:
    result_bytes = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    manifest = {"schema_version": 1, "created_ts": time.time(), "files": {"assessment.json": hashlib.sha256(result_bytes).hexdigest()}}
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["hmac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest() if key else ""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("assessment.json", result_bytes)
        bundle.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
    return manifest


def coverage(result: dict, expected_rules: set[str] | None = None) -> dict:
    tests = result["results"]
    observed = {alert["rule_id"] for test in tests for alert in test.get("alerts", [])}
    expected = expected_rules or {rule for test in tests for assertion in test.get("assertions", []) if assertion["name"] == "rule_ids" for rule in assertion["expected"]}
    evidence_fields = sorted({key for test in tests for alert in test.get("alerts", []) for key in (alert.get("evidence") or {})})
    return {"tests_total": len(tests), "tests_passed": sum(t["status"] == "passed" for t in tests), "rules_expected": sorted(expected), "rules_observed": sorted(observed), "rule_coverage_percent": round(100 * len(observed & expected) / len(expected), 1) if expected else 100.0, "evidence_fields": evidence_fields}
