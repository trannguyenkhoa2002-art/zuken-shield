"""Repeatable lightweight collector benchmark: `shield-benchmark`."""

from __future__ import annotations

import argparse
import json
import resource
import statistics
import time
from pathlib import Path

from shield.agent.collectors.endpoint import fim_snapshot, network_snapshot, process_snapshot, usb_snapshot


def run_benchmark(iterations: int = 5, fim_paths: list[Path] | None = None) -> dict:
    iterations = max(1, min(iterations, 100))
    samples = []
    counts = {}
    for _ in range(iterations):
        started = time.perf_counter()
        processes = process_snapshot()
        network = network_snapshot()
        usb = usb_snapshot()
        fim = fim_snapshot(fim_paths or [])
        samples.append((time.perf_counter() - started) * 1000)
        counts = {"processes": len(processes), "listeners": len(network), "usb": len(usb), "fim": len(fim)}
    rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "iterations": iterations, "mean_ms": round(statistics.mean(samples), 3),
        "p95_ms": round(sorted(samples)[max(0, int(len(samples) * 0.95) - 1)], 3),
        "max_rss_kib": int(rss_kib), "counts": counts,
        "pass": statistics.mean(samples) < 1000 and rss_kib < 512 * 1024,
        "thresholds": {"mean_ms": 1000, "max_rss_kib": 512 * 1024},
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="shield-benchmark")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--fim-path", action="append", default=[])
    args = parser.parse_args()
    result = run_benchmark(args.iterations, [Path(p).expanduser() for p in args.fim_path])
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["pass"] else 1)


if __name__ == "__main__":
    main()
