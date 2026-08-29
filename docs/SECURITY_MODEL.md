# Security Model

What runs with which privileges, where the boundaries are, and what Shield
refuses to do.

## Processes and privileges

| Component | Runs as | Why |
|---|---|---|
| `shield-agent` | root | kernel telemetry (eBPF), packet capture, reading system logs |
| `shield-privileged` | root | applies network and process actions through a fixed operation set |
| `shield` (interface) | your user | reads and displays; holds no privilege of its own |
| AI worker | unprivileged, isolated | dormant in Beta 1.0; see below |

The agent is confined by its systemd unit: `MemoryMax=1G`, `TasksMax=512`, and a
restricted capability set.

## Boundaries

**Interface → agent.** A Unix socket at `/run/shield/shield.sock`, reachable by
members of the `shield` group. The command set is closed: the agent accepts a
fixed list of named commands and rejects everything else. The interface cannot
run code in the agent.

**Agent → privileged helper.** A separate Unix socket. The helper exposes a
fixed operation set — block an address, rate-limit, isolate the endpoint,
release isolation, stop a process, report health. The agent cannot ask it to run
an arbitrary command; there is no shell path.

**Response policy.** Every action has an entry in the action table declaring its
level, blast radius, reversibility, preconditions, and rollback. Actions are
verified against observable system state after execution, and rolled back when
verification fails. A failure raises an alert rather than passing silently.

## Evidence integrity

- No graph edge may exist without a valid evidence reference. An assertion
  nobody can check later is treated as a bug.
- A forensic ledger is verified at startup, and truncation or corruption raises
  an alert.
- Database integrity is checked during maintenance; failure raises a critical
  alert.
- Reports state an epistemic state derived from validated evidence, never
  guessed.

## Secret handling

Redaction runs before anything is stored and again before display: private keys,
tokens, passwords, and similar patterns are replaced. The red-team corpus in the
repository exists to keep that path honest, including deliberately awkward cases
such as secrets nested inside harmless-looking fields.

## The AI boundary

Dormant in Beta 1.0 — no feature starts a model. The confinement is documented
because the code is present and will be used again.

When a model does run, it runs in a **separate process** with:

- a transient systemd scope: `MemoryMax=2560M`, `MemorySwapMax=0`,
  `CPUQuota=300%`, `TasksMax=96`
- **no network** — the worker unshares its network namespace, or is wrapped by
  `bwrap --unshare-net`; if neither is available it refuses to start
- self-applied resource limits, and privileges dropped before the model loads
- no database handle, no capability token, no tool registry
- a strict length-prefixed JSON protocol, and grammar-constrained decoding so a
  tool request cannot be represented, let alone emitted
- at most one model worker on the machine at a time

Every generated sentence passes a single validator that drops any prose
inventing a value not present in the canonical data, or claiming certainty
Shield does not have. There is one such gate, deliberately, so a second copy
cannot drift from it.

A model can never set severity, scenario, evidence references, counts,
identifiers, timestamps, or recommendations.

## Kill switch

A kill switch disables all model-backed work immediately. It does not affect
detection, reporting, or deterministic Q&A — a switch that also disabled
monitoring would be a switch nobody dares use.

## What Shield deliberately does not do

- No outbound network communication for its own purposes.
- No arbitrary command execution from the interface or the agent.
- No autonomous action driven by a model.
- No exploitation, scanning-for-weakness, or credential attacks.
- No silent failure: when isolation or validation is unavailable, Shield does
  less and says so.

## Threat model, honestly stated

Shield assumes the host is not already fully compromised at the kernel level. An
attacker with root on the monitored machine can stop the agent, and the guardian
service will alert on that but cannot prevent it.

Shield defends against: unnoticed activity on a host you own, local network
tampering, and the loss of evidence after an event. It does not defend against a
kernel rootkit, and it is not a substitute for patching, least privilege, or
backups.

Beta 1.0 has not had an independent privilege-boundary review. That review is
listed in `../ROADMAP.md` as a prerequisite for a stable release.
