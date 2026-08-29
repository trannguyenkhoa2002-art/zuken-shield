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
- On the development machine, the agent has occasionally been restarted by the
  systemd watchdog around boot. The database maintenance path — the previous
  cause of exactly this symptom — was measured and bounded in this release and
  is not responsible. The remaining trigger is unidentified and is recorded here
  rather than omitted.

## Licensing

The source is offered under Apache-2.0. **The licence of the distributed
combination is an open question**: the interface depends on PyQt6 (GPL-3.0) and
the agent on scapy (partly GPL-2.0). `../NOTICE` states the problem and the
available options. Resolve it before redistributing binaries.

## Upgrading

There is no earlier public release, so there is no upgrade path to document.
Internally, upgrades from `3.0.0a1` migrate the schema additively and preserve
existing events, alerts, and devices.

Note that a package install rebuilds the agent's virtualenv from scratch by
design. If you installed the optional `llama-cpp-python` runtime, reinstall it
afterwards. Nothing in Beta 1.0 requires it.
