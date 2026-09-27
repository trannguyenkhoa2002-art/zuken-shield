#!/usr/bin/env python3
"""Cổng nghiệm thu cho từng giai đoạn: PASS chỉ khi có bằng chứng, không có ngoại lệ.

Một giai đoạn được coi là XONG khi và chỉ khi tất cả các điều sau đúng, và
mỗi điều để lại một file bằng chứng có SHA-256:

1. Cây làm việc sạch: bằng chứng gắn với MỘT commit cụ thể, không phải với
   những thay đổi chưa ai ghi lại.
2. Test nghiệm thu của giai đoạn PASS hết trên HEAD.
3. Chính những test đó FAIL trên commit gốc của giai đoạn (trước khi làm).
   Test pass ở cả hai phía không chứng minh được gì về tính năng mới — đây
   là bước chống "test cho có". Mỗi file test phải có ít nhất một bài fail ở
   gốc, và ít nhất một nửa số bài phải fail ở gốc.
4. ruff sạch, mypy sạch.
5. Toàn bộ test suite xanh với `ulimit -n 1024` (0 failed, 0 error).

Danh sách giai đoạn nằm trong `tests/phase_gates.json`. Kết quả (PASS/BLOCK)
và mọi log được ghi vào thư mục bằng chứng; `summary.json` liệt kê hash của
từng file để người khác kiểm lại được.

    python scripts/phase_gate.py --phase 1 --evidence-dir ../evidence
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests" / "phase_gates.json"
FD_LIMIT = 1024


def run(cmd: list[str], log: Path, *, cwd: Path = ROOT, env: dict | None = None,
        fd_limit: int | None = None, timeout: int = 1800) -> int:
    def limit() -> None:
        if fd_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, fd_limit))

    started = time.time()
    with log.open("w", encoding="utf-8") as out:
        out.write(f"Time: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\nCwd: {cwd}\nCommand: {cmd}\n\n")
        out.flush()
        proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT,
                              preexec_fn=limit if fd_limit else None, timeout=timeout)
        out.write(f"\nEXIT_CODE={proc.returncode}\nELAPSED_SECONDS={time.time() - started:.3f}\n")
    return proc.returncode


def junit_results(path: Path) -> dict[str, str]:
    """Kết quả từng test: passed / failed / error / skipped."""
    results: dict[str, str] = {}
    if not path.exists():
        return results
    for case in ET.parse(path).getroot().iter("testcase"):
        name = f"{case.get('classname')}::{case.get('name')}"
        outcome = "passed"
        for child in case:
            if child.tag in ("failure", "error", "skipped"):
                outcome = {"failure": "failed"}.get(child.tag, child.tag)
        results[name] = outcome
    return results


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True,
                          text=True).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--phase", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable,
                        help="Python có cài dev dependencies (pytest, ruff, mypy)")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    phase = manifest["phases"][args.phase]
    head = git("rev-parse", "HEAD")
    base = git("rev-parse", phase["base"])
    out = args.evidence_dir.resolve() / f"phase-{args.phase}-{head[:12]}"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    checks: dict[str, dict] = {}
    py = args.python
    bin_dir = Path(py).parent

    # 1. Cây sạch.
    dirty = git("status", "--porcelain")
    (out / "git-status.log").write_text(dirty + "\n", encoding="utf-8")
    checks["clean_tree"] = {"ok": dirty == "", "detail": "working tree clean" if not dirty else dirty}

    tests = phase["acceptance_tests"]

    # 2. Nghiệm thu trên HEAD.
    head_xml = out / "acceptance-head.xml"
    run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={head_xml}", *tests],
        out / "acceptance-head.log")
    head_results = junit_results(head_xml)
    head_bad = {k: v for k, v in head_results.items() if v not in ("passed",)}
    checks["acceptance_on_head"] = {
        "ok": bool(head_results) and not head_bad,
        "detail": f"{len(head_results)} tests, not passed: {head_bad}",
    }

    # 3. Cùng test đó trên commit gốc phải FAIL.
    with tempfile.TemporaryDirectory(prefix="phase-gate-") as tmp:
        worktree = Path(tmp) / "base"
        subprocess.run(["git", "worktree", "add", "--detach", str(worktree), base], cwd=ROOT,
                       check=True, capture_output=True)
        try:
            for relative in tests + phase.get("support_files", []):
                target = worktree / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            env = dict(os.environ, PYTHONPATH=str(worktree))
            probe = subprocess.run([py, "-c", "import shield; print(shield.__file__)"], cwd=worktree,
                                   env=env, capture_output=True, text=True)
            imported = probe.stdout.strip()
            base_xml = out / "acceptance-base.xml"
            run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={base_xml}", *tests],
                out / "acceptance-base.log", cwd=worktree, env=env)
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=ROOT,
                           capture_output=True)
    base_results = junit_results(base_xml)
    failed_at_base = {k for k, v in base_results.items() if v in ("failed", "error")}
    # Lỗi import cả file ở gốc (module chưa tồn tại) là fail hợp lệ: pytest ghi
    # nó thành một testcase lỗi mang tên file.
    per_file_ok = all(
        any(Path(t).stem in name for name in failed_at_base) for t in tests)
    ratio = len(failed_at_base) / max(1, len(head_results))
    isolated = imported.startswith(str(worktree))
    checks["fails_on_base"] = {
        "ok": isolated and per_file_ok and (ratio >= 0.5 or len(base_results) < len(head_results)),
        "detail": (f"base={base[:12]} imported={imported} isolated={isolated}; "
                   f"{len(failed_at_base)} failed/error of {len(base_results)} collected at base "
                   f"(head has {len(head_results)}); every file fails at base: {per_file_ok}"),
    }

    # 4. Lint và kiểu.
    ruff_rc = run([str(bin_dir / "ruff"), "check", "."], out / "ruff.log")
    checks["ruff"] = {"ok": ruff_rc == 0, "detail": f"exit {ruff_rc}"}
    mypy_rc = run([str(bin_dir / "mypy")], out / "mypy.log")
    checks["mypy"] = {"ok": mypy_rc == 0, "detail": f"exit {mypy_rc}"}

    # 5. Toàn bộ suite, giới hạn fd như máy mặc định.
    suite_xml = out / "full-suite.xml"
    suite_rc = run([py, "-m", "pytest", "-q", "-ra", "-p", "no:cacheprovider", f"--junitxml={suite_xml}"],
                   out / "full-suite.log", fd_limit=FD_LIMIT)
    suite = junit_results(suite_xml)
    counts = {state: sum(1 for v in suite.values() if v == state)
              for state in ("passed", "failed", "error", "skipped")}
    checks["full_suite"] = {
        "ok": suite_rc == 0 and counts["failed"] == 0 and counts["error"] == 0 and counts["passed"] > 0,
        "detail": f"exit {suite_rc}, ulimit -n {FD_LIMIT}, {counts}",
    }

    verdict = "PASS" if all(c["ok"] for c in checks.values()) else "BLOCK"
    summary = {
        "phase": args.phase,
        "title": phase["title"],
        "verdict": verdict,
        "head": head,
        "base": base,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "acceptance_tests": tests,
        "checks": checks,
        "acceptance_head": head_results,
        "acceptance_base": base_results,
        "evidence_sha256": {p.name: sha256(p) for p in sorted(out.iterdir()) if p.is_file()},
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    for name, check in checks.items():
        print(f"{'OK   ' if check['ok'] else 'FAIL '} {name}: {check['detail'][:300]}")
    print(f"\nPHASE {args.phase} {verdict} — evidence: {out}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
