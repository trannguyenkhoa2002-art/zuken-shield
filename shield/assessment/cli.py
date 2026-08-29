from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import zipfile
from pathlib import Path

from shield.agent.detectors.endpoint import EndpointDetector
from shield.assessment.exporters import coverage, export_evidence_bundle, export_junit, export_sarif
from shield.assessment.models import AssessmentProfile
from shield.assessment.replay import load_jsonl, replay
from shield.assessment.runner import AssessmentRunner
from shield.security.rules import RuleDetector


def default_detectors() -> list:
    rule_path = Path(__file__).resolve().parent.parent / "rules" / "default.json"
    return [EndpointDetector(), RuleDetector.from_file(rule_path)]


def verify_bundle(path: Path, key: bytes = b"") -> tuple[bool, str]:
    try:
        with zipfile.ZipFile(path) as bundle:
            result = bundle.read("assessment.json")
            manifest = json.loads(bundle.read("manifest.json"))
        expected = manifest["files"]["assessment.json"]
        if not hmac.compare_digest(hashlib.sha256(result).hexdigest(), expected):
            return False, "hash mismatch"
        signature = str(manifest.pop("hmac", ""))
        if signature:
            if not key:
                return False, "bundle is signed; verification key required"
            canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            expected_signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected_signature):
                return False, "signature mismatch"
            return True, "verified (HMAC signed)"
        return True, "verified (unsigned)"
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        return False, str(exc)


def main() -> None:
    parser = argparse.ArgumentParser(prog="shield-assess")
    sub = parser.add_subparsers(dest="command", required=True)
    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("profile", nargs="?", type=Path, default=Path(__file__).resolve().parent / "default-profile.json")
    run_cmd.add_argument("--output", type=Path, default=Path("shield-assessment-output"))
    run_cmd.add_argument("--hmac-key-file", type=Path)
    replay_cmd = sub.add_parser("replay")
    replay_cmd.add_argument("events", type=Path)
    replay_cmd.add_argument("--output", type=Path, default=Path("replay-result.json"))
    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("bundle", type=Path)
    verify_cmd.add_argument("--hmac-key-file", type=Path)
    args = parser.parse_args()

    if args.command == "verify":
        key = args.hmac_key_file.read_bytes() if args.hmac_key_file else os.environ.get("SHIELD_ASSESSMENT_HMAC_KEY", "").encode()
        ok, message = verify_bundle(args.bundle, key)
        print(message)
        raise SystemExit(0 if ok else 4)
    if args.command == "replay":
        result = replay(load_jsonl(args.events), default_detectors())
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(args.output)
        raise SystemExit(0)

    profile = AssessmentProfile.load(args.profile)
    result = asyncio.run(AssessmentRunner(default_detectors()).run(profile)).to_dict()
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "assessment.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    export_junit(result, args.output / "junit.xml")
    export_sarif(result, args.output / "results.sarif")
    key = args.hmac_key_file.read_bytes() if args.hmac_key_file else os.environ.get("SHIELD_ASSESSMENT_HMAC_KEY", "").encode()
    export_evidence_bundle(result, args.output / "evidence.zip", key)
    (args.output / "coverage.json").write_text(json.dumps(coverage(result), indent=2), encoding="utf-8")
    print(args.output)
    counts = {status: sum(item["status"] == status for item in result["results"]) for status in ("passed", "failed", "inconclusive", "skipped")}
    raise SystemExit(0 if counts["failed"] == 0 and counts["inconclusive"] == 0 else 1)


if __name__ == "__main__":
    main()
