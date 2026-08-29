# Release Notes — Zuken Shield Beta 1.0

**Product release:** Beta 1.0
**Package version:** `3.0.0a2`
**Date:** 2026-08-29

## About the two version numbers

The package reports `3.0.0a2` because that is the version the code was developed,
tested, and released under internally. "Beta 1.0" is the public name for this
release.

The numbers were deliberately not merged. Rewriting the package version purely
for presentation would mean the version in `dpkg`, in the interface, and in the
gate report no longer matched the artefacts they were tested as. A version number
that lies about provenance is a poor trade for a tidier headline.

The recommended path is to align them at the first stable release — publish
`1.0.0` when the beta criteria in `../ROADMAP.md` are met, and treat `3.0.0a2` as
the last internal number.

## What this release is

An evidence-driven Linux security monitoring and investigation platform for a
single host and the network around it. It collects telemetry, detects, correlates
into incidents, preserves evidence, and produces reports where every statement is
traceable to a stored event.

See `../CHANGELOG.md` for the feature list.

## Artificial intelligence: what actually happened

Beta 1.0 uses **no language model**. This is a measured outcome, not a decision
made on principle, and the measurements are worth stating because they explain
the shape of the product.

**Scenario classification.** A local model was evaluated against a deterministic
registry lookup for classifying incidents. The model scored 54.8%; the registry
scored 100%. The model was removed from that role entirely.

**Explanation prose.** A local model was then evaluated for writing explanation
prose on qualified scenarios. It passed for one family, passed with per-scenario
gating for another, and failed a third at 94.7% against a 95% bar — which was
left as a failure rather than rounded up.

**Guided Q&A summary.** For the incident summary answer, the model failed twice
over, on real incidents:

- With the process identity in context, it truncated `426601:4193241` to
  `426601:419324` — one digit — in **12 of 12 attempts** at temperature 0. The
  output validator correctly destroyed every answer, because an identifier wrong
  in its last digit is worse than no answer.
- With the identity withheld, 12 of 12 answers survived the validator but opened
  by calling a suspicious execution chain "a network attack" — the wrong incident
  class. The value guard cannot catch that, because it is an assertion rather
  than a fabricated number.

Both failure modes were unacceptable, so all five guided Q&A intents are
deterministic. They answer in roughly a millisecond, render identifiers verbatim
from the database, and cannot mislabel an incident because the scenario name
comes from the registry.

The isolated worker infrastructure was kept — process isolation, cgroup limits,
network removal, grammar-constrained decoding, and the single output gate — so a
better model can be evaluated later against the criteria in `../ROADMAP.md`.

**Shield is therefore not an AI product, and this release does not market itself
as one.**

## Fixed in this release

**Startup watchdog timing defect.** `shield-agent` uses `Type=simple`, so
systemd counts `WatchdogSec` from service start rather than from `READY=1`. The
watchdog loop slept a full interval before its first ping, making the real
deadline `startup time + interval`. A measured cold start of 46.0 s plus the
45 s interval exceeded the 90 s limit by one second, so the agent was killed by
the watchdog on cold boot only — which is why the symptom looked random for
weeks.

The fix sends the first `WATCHDOG=1` immediately after the store-health check
succeeds, before the first sleep. The ping is still conditional on the event
loop running and the database answering, so it proves liveness rather than mere
process existence. `WatchdogSec` was not raised; a test enforces both the early
ping and the fact that the limit was not simply loosened.

Verified by 16 clean service starts with `NRestarts=0` and no watchdog kills,
then a real cold reboot: `shield-agent` active, `Result=success`, `NRestarts=0`,
and a current-boot watchdog-timeout count of zero.

## Other changes in this release

- **Interface migrated from PyQt6 to PySide6.** PyQt6 is offered only under
  GPL-3.0 or a commercial licence; PySide6 and Qt 6 are used under their
  LGPL-3.0 option, with no bundling and no static linking.
- **Packet capture separated from the core.** The scapy (GPL-2.0) dependency
  now lives in the optional `shield-packet-collector` — its own program,
  package, process, and systemd unit, running with `CAP_NET_RAW` and
  `CAP_NET_ADMIN` only. It feeds the core newline-delimited JSON over a Unix
  socket against a closed schema, and the core treats it as untrusted input.
- **A core-only install no longer depends on scapy.** An AST scan over the whole
  core runs in the test suite and fails if a scapy import appears. Without the
  helper, Shield reports the affected capabilities as unavailable rather than
  failing.
- **All five guided Q&A intents are deterministic**, and no language model is
  required or started by any feature in Beta 1.0.

## Verification

At release:

- 2260 tests collected; 2225 passing unprivileged; 35 requiring root and skipped
- Live acceptance on the developer's own machine against real production
  telemetry, with the AI runtime deliberately absent
- Guided Q&A verified across five intents, two languages, and three gate
  configurations — 30 combinations, all deterministic, zero model workers started
- Package upgrade verified to preserve evidence and migrate the schema additively

## Known limitations

The full list is in `../README.md`. The ones most likely to matter:

- Single host. No fleet management, no central console.
- No independent security review; no completed soak testing.
- Kernel telemetry requires `bpftrace`; without it endpoint visibility is
  reduced, and Shield reports the reduction rather than hiding it.
- Detection thresholds were tuned against one real environment.
- Response actions beyond `block_ip` have had limited real-world exercise.
- The startup watchdog defect described above is fixed and verified, but the
  verification is repeated starts and one real cold boot — not long-duration
  soak testing.

## Licensing

The source is offered under Apache-2.0. The interface uses the
system-provided PySide6 and Qt 6 packages under their LGPL-3.0 option; Shield
bundles and statically links neither. scapy (GPL-2.0) is no longer a core
dependency — it belongs to the optional `shield-packet-collector`, a separate
program and process. `../NOTICE` records the dependency list, the LGPL-3.0
obligations, and the packet-helper boundary, and states plainly that the
separation is architectural rather than a legal conclusion. The helper's own
licence position still needs review by whoever distributes it.

## Upgrading

There is no earlier public release, so there is no upgrade path to document.
Internally, upgrades from `3.0.0a1` migrate the schema additively and preserve
existing events, alerts, and devices.

Note that a package install rebuilds the agent's virtualenv from scratch by
design. If you installed the optional `llama-cpp-python` runtime, reinstall it
afterwards. Nothing in Beta 1.0 requires it.
