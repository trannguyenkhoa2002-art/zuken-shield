# Roadmap

Nothing here is a commitment or a date. This is what the maintainers consider
worth doing next, and why. Items move to `CHANGELOG.md` only when they exist in
code with tests.

## Before calling anything "1.0 Stable"

These are the gaps that keep Beta 1.0 a beta.

- **Independent security review** of the privilege boundary: the IPC socket, the
  privileged helper's operation set, TOCTOU handling, symlink handling, and the
  package maintainer scripts.
- **Soak testing** at 24 hours, 72 hours, 7 days, and 30 days on the packaged
  build, with memory, database growth, and event-loop latency recorded.
- **Resolve the startup watchdog restarts** observed on the development machine.
  The database maintenance path was measured and bounded in Beta 1.0 and is not
  the cause; the remaining trigger is unidentified.
- **Settle the scapy position** described in `NOTICE`. The PyQt6 (GPL-3.0)
  dependency was removed by migrating the interface to PySide6 under LGPL-3.0.
  What remains is scapy (GPL-2.0), imported by four packet-capture collectors,
  not vendored and not bundled. Either accept it as a system dependency, or move
  those collectors behind a process boundary as `probe/` already demonstrates.
- **Database restore and package rollback** validated on every supported release.

## Detection

- Dedicated DHCP, mDNS, and SSDP/UPnP collectors for richer device profiling.
- Per-device time-series baselines rather than global thresholds.
- Production YARA execution.
- Detection tuning against environments other than the developer's own, which is
  currently the only real-world sample.

## Response

- Exercise the actions above `block_ip` — rate limiting, endpoint isolation,
  process stop — in a disposable virtual machine, with rollback results
  recorded for each.
- Clearer operator preview of what an action will do before it runs.

## Evidence and reporting

- Broader scenario coverage; a number of scenarios are deterministic-report-only
  today because their evidence shape has not been validated.
- Report export beyond the current formats.

## Local AI — only if it earns its place

The infrastructure exists and is dormant. A model will be enabled for a feature
only when it passes a measured gate, per intent, on real incidents:

- Deterministic intent mapping stays at 100%; the model is never asked to
  classify anything.
- Useful answers at or above 80%, grounded at or above 95%, zero contradictions,
  zero fabricated canonical values.
- Equivalent quality in Vietnamese and English, since Vietnamese is the default.
- Latency compatible with interactive use.

Qwen2.5-1.5B was evaluated for the incident summary and failed: it truncated a
process identifier in every attempt, and when the identifier was withheld it
mislabelled the incident type. That measurement is why guided Q&A is
deterministic today. A larger or better-suited local model may change the
result; marketing will not.

## Explicitly not planned

- Cloud services, remote analysis, or telemetry upload.
- A general chat assistant.
- Autonomous response driven by a language model.
- Offensive or exploitation features.
