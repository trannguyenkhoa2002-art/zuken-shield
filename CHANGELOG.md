# Changelog

Public history starts at Beta 1.0. Development before this point was internal
and is not reproduced here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Beta 1.0] — 2026-08-29

Internal package version: `3.0.0a2`.

First public release.

### Monitoring and detection

- Endpoint telemetry: process execution, file writes, and outbound socket
  connections through eBPF/bpftrace where the kernel supports it, with measured
  per-event-kind coverage reporting rather than assumed coverage.
- File integrity monitoring, listening-socket inventory, USB device events,
  journal and auditd ingestion, and syslog reception from authorised sources.
- Network telemetry: ARP and neighbour observation, DNS resolver monitoring,
  connection and flow aggregation, device discovery, and traffic statistics.
- 58 detection rule identifiers spanning authentication attacks,
  reconnaissance, malware-execution behaviour chains, network tampering
  (ARP, DNS, DHCP, ICMP redirect), device inventory, file and configuration
  tampering, risky service exposure, and Shield's own integrity.
- Correlation of related alerts into incidents, including multi-step chains.

### Evidence and investigation

- Evidence graph with 12 entity types and 11 relations, enforcing that no edge
  exists without a valid evidence reference.
- Expert Evidence: a read-only query surface over the event store, with hard
  row limits, timeouts, redaction, and an audit trail.
- Deterministic incident reports: ten fixed sections built only from measured
  data, each carrying an explicit epistemic state.
- Guided incident Q&A: five closed questions — summarise, explain evidence, how
  certain, related process, what to inspect next — answered deterministically
  from the report in roughly a millisecond. Questions outside the set, and
  requests to take action, are refused deterministically.

### Response

- Six action types with declared level, blast radius, reversibility,
  preconditions, and rollback.
- Actions verified against observable system state rather than assumed to have
  worked; automatic rollback when verification fails.
- A privileged helper exposing a fixed operation set over a Unix socket, so the
  agent never executes arbitrary commands.

### Robustness

- Bounded database maintenance: retention deletes, size-cap trimming, and
  evidence-graph pruning are each capped per pass and resume on the next tick,
  so maintenance cannot hold the database lock long enough to miss the systemd
  watchdog.
- Guardian service, forensic ledger verification, database integrity checks, and
  alerts when Shield's own collectors go quiet or fail.
- Isolated worker infrastructure for future local model work: separate process,
  transient systemd scope with memory and CPU limits, network removed, strict
  output validation, and one global worker at a time.

### Interface

- Vietnamese and English throughout.
- Incident report and guided Q&A on the incidents screen, with evidence
  references that open the Expert Evidence viewer.

### Privacy

- All data stays on the machine. No cloud service, no telemetry upload, no
  remote AI.
- Secret redaction applied before storage and before display.

### Known limitations

- Single host. No fleet management or central console.
- No independent security review, and no completed 24h/72h/7-day soak testing.
- Kernel telemetry requires `bpftrace`; without it, endpoint visibility is
  reduced, and Shield reports the reduced coverage rather than concealing it.
- Detection thresholds are tuned against one real environment.
- Response actions beyond `block_ip` have had limited real-world exercise.
- Interface is Vietnamese and English only.
- The startup watchdog timing defect that restarted the agent around cold boot
  was identified and fixed in this release. It is verified across repeated
  service starts and a real cold boot with zero watchdog timeouts, but not yet
  over a long-duration soak.
- No language model is used by any feature. The isolated worker infrastructure
  is present but dormant; see the release notes for why.
