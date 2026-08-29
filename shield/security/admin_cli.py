"""Administrative CLI for offline fleet enrollment and release gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from shield.agent.store import Store
from shield.assessment.lab import evaluate_release_gate
from shield.security.fleet import FleetRegistry
from shield.security.diagnostics import export_diagnostic_bundle


def main() -> None:
    parser = argparse.ArgumentParser(prog="shield-admin")
    parser.add_argument("--db", type=Path, help="Override Shield database path")
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("fleet-enroll")
    enroll.add_argument("--name", required=True)
    enroll.add_argument("--cert", required=True, type=Path)
    enroll.add_argument("--role", choices=("viewer", "analyst", "administrator"), default="viewer")
    commands.add_parser("fleet-list")
    gate = commands.add_parser("release-gate")
    gate.add_argument("results", type=Path)
    diagnostics = commands.add_parser("diagnostics")
    diagnostics.add_argument("--output", required=True, type=Path)

    # Probe (KE-HOACH-SHIELD-1.1.md mục A1). Tách khỏi fleet-enroll vì role
    # `probe` có ý nghĩa khác hẳn: nó chỉ được GỬI LOG LÊN, không bao giờ
    # nhận lệnh xuống — xem security/fleet.py.
    probe_enroll = commands.add_parser(
        "probe-enroll", help="Cho phép một Shield Probe gửi log về máy này")
    probe_enroll.add_argument("--name", required=True)
    group = probe_enroll.add_mutually_exclusive_group(required=True)
    group.add_argument("--cert", type=Path, help="Đường dẫn probe.crt")
    group.add_argument("--fingerprint", help="SHA256 của DER, do generate-probe-ca.sh in ra")
    commands.add_parser("probe-list", help="Danh sách probe đã ghi danh và tình trạng")
    probe_revoke = commands.add_parser("probe-revoke", help="Thu hồi quyền gửi log của một probe")
    probe_revoke.add_argument("endpoint_id")

    args = parser.parse_args()

    if args.command == "release-gate":
        result = evaluate_release_gate(json.loads(args.results.read_text(encoding="utf-8")))
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 5)

    store = Store(args.db) if args.db else Store()
    try:
        if args.command == "fleet-enroll":
            endpoint = FleetRegistry(store).enroll(args.name, args.cert.read_bytes(), args.role)
            store.add_forensic_record("fleet_enrollment", {"endpoint_id": endpoint.endpoint_id,
                                      "fingerprint": endpoint.certificate_fingerprint, "role": endpoint.role})
            print(json.dumps(endpoint.__dict__, indent=2))
        elif args.command == "fleet-list":
            print(json.dumps(store.list_endpoints(), indent=2))
        elif args.command == "probe-enroll":
            registry = FleetRegistry(store)
            if args.cert:
                endpoint = registry.enroll(args.name, args.cert.read_bytes(), "probe")
            else:
                endpoint = registry.enroll_fingerprint(args.name, args.fingerprint, "probe")
            store.add_forensic_record("probe_enrollment", {
                "endpoint_id": endpoint.endpoint_id,
                "fingerprint": endpoint.certificate_fingerprint, "role": endpoint.role,
            })
            print(json.dumps(endpoint.__dict__, indent=2))
        elif args.command == "probe-list":
            probes = [e for e in store.list_endpoints() if e["role"] == "probe"]
            health = {h["probe_id"]: h for h in store.list_probe_health()}
            for probe in probes:
                probe["health"] = health.get(probe["endpoint_id"], {})
            print(json.dumps(probes, indent=2))
        elif args.command == "probe-revoke":
            removed = store.revoke_endpoint(args.endpoint_id)
            store.add_forensic_record("probe_revocation", {
                "endpoint_id": args.endpoint_id, "removed": removed,
            })
            print(json.dumps({"endpoint_id": args.endpoint_id, "revoked": removed}, indent=2))
            raise SystemExit(0 if removed else 4)
        else:
            manifest = export_diagnostic_bundle(store, args.output)
            print(json.dumps({"output": str(args.output.resolve()), "manifest": manifest}, indent=2))
    finally:
        store.close()


if __name__ == "__main__":
    main()
