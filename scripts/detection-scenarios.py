#!/usr/bin/env python3
"""Chạy 20 kịch bản xác thực phát hiện và ghi báo cáo bằng chứng.

    python scripts/detection-scenarios.py --out <thư_mục>

Ghi ra: summary.json (kết quả từng kịch bản, có SHA-256 tự chứng), và
report.md (bảng người đọc). Mỗi kịch bản chạy trên một database tạm riêng qua
đúng đường ống của agent — xem shield/assessment/detection_scenarios.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys  # noqa: E402

sys.path.insert(0, str(ROOT))
from shield import __version__  # noqa: E402
from shield.assessment.detection_scenarios import SCENARIOS, run_scenario  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    results = []
    with tempfile.TemporaryDirectory(prefix="detection-scenarios-") as tmp:
        for index, scenario in enumerate(SCENARIOS):
            results.append(run_scenario(scenario, Path(tmp) / f"{index:02d}-{scenario.id}.db"))

    passed = sum(r["passed"] for r in results)
    summary = {
        "shield_version": __version__,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "note": ("Kiểm thử PHÒNG THỦ: phát lại telemetry của hành vi tấn công qua đường ống thật "
                 "của agent (detector, chấm điểm, vùng xám, correlation). Không thực hiện tấn công."),
        "total": len(results),
        "passed": passed,
        "detection_rate": round(passed / len(results), 4),
        "scenarios": results,
    }
    summary_path = args.out / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        f"# Xác thực khả năng phát hiện — {passed}/{len(results)} kịch bản",
        "",
        f"Shield {__version__} · {summary['time']}",
        "",
        summary["note"],
        "",
        "| # | Kịch bản | MITRE | Hành vi tấn công | Phát hiện | Risk/Conf | Kết quả |",
        "|---|---|---|---|---|---|---|",
    ]
    for index, r in enumerate(results, 1):
        detected = []
        for rule, score in r["detected_alerts"].items():
            detected.append(f"{rule} ({score['risk']}/{score['evidence_confidence']})")
        extra = []
        if r["incidents"]:
            extra.append("incident: " + ", ".join(r["incidents"]))
        if r["gray_zone_kinds"]:
            extra.append("vùng xám: " + ", ".join(r["gray_zone_kinds"]))
        want = (", ".join(r["expected_alerts"]) or r["expected_gray_zone"]
                or r["expected_incident"] or "-")
        got = "; ".join(detected) or "-"
        if extra:
            got += "  \n" + "; ".join(extra)
        lines.append(
            f"| {index} | {r['title']} | {r['technique']} | {r['attacker_action']} | "
            f"{want} | {got} | {'✅ PASS' if r['passed'] else '❌ FAIL'} |")
    lines += [
        "",
        f"**Tỷ lệ phát hiện: {passed}/{len(results)} ({summary['detection_rate'] * 100:.0f}%).**",
        "",
        "Mỗi 'Phát hiện' ghi kèm (Behavior Risk / Evidence Confidence). Các mục vùng xám "
        "`below_threshold` là hoạt động dưới ngưỡng được giữ lại cho người phân tích thay "
        "vì bị bỏ im lặng; `low_confidence` là alert nguy hiểm nhưng chưa đủ bằng chứng.",
        "",
        "## Quan sát",
        "",
        "- Cổng 4444 (Metasploit) và 445 (SMB) đi qua HAI đường phát hiện khác nhau: 4444 khớp "
        "rule `ENDPOINT_LISTENER_ON_REMOTE_ACCESS_PORT`, 445 khớp detector "
        "`ENDPOINT_SENSITIVE_LISTENER_OPENED`. Hai danh sách cổng không trùng khít nhau "
        "(detector: 23/445/3389/5900; rule: 23/3389/5900/5901/4444/1080). Cả hai cổng đều được "
        "phát hiện; việc hợp nhất hai danh sách là một quyết định về ngưỡng, không phải lỗi.",
    ]
    report_path = args.out / "report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    sha = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
           for p in (summary_path, report_path)}
    (args.out / "evidence-sha256.txt").write_text(
        "\n".join(f"{h}  {n}" for n, h in sha.items()) + "\n", encoding="utf-8")
    print(f"{passed}/{len(results)} scenarios detected → {args.out}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
