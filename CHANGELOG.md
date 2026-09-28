# Changelog

Public history starts at Beta 1.0. Development before this point was internal
and is not reproduced here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — internal package version `3.0.0a3`

### Added

- **Behavior Risk vs. Evidence Confidence** (phase 1): two scores per alert;
  declarative evidence models for SSH brute force, port scan, gateway MAC change,
  ARP conflict, DNS resolver change and rogue DHCP list observed and missing
  evidence. DNS change and rogue DHCP corroborate each other when close in time.
- Evidence-graph edges keep their first 8 evidence refs plus the 24 newest,
  instead of only the first 32 (which had all expired on long-lived edges).
- **Gray zone** (phase 2): near-misses, low-confidence and suppressed signals
  are recorded for the analyst; only a person promotes (audited incident with an
  `analyst_promoted` reason) or dismisses them.
- **Raw log lines** (phase 3): journal, auditd, syslog and probe events keep
  the original line, redacted and capped, next to the normalized event.
- **Live workspace** (phase 4): up to ten filtered tabs with Live / Pause /
  Search / Replay, groups discovered from telemetry, entity lifetime history.
- Each phase passed `scripts/phase_gate.py`: acceptance tests pass on the phase
  and fail on the commit before it, ruff, mypy, full suite at `ulimit -n 1024`.

### Fixed

- Journal, syslog and probe stored the verbatim `message` in normalized data
  without secret redaction.
- Near-misses could have been counted as detections by replay, assessment and
  eval runners; they are filtered.
- Automatic backups are pruned after the new copy is written (pruning first
  left one extra copy and could remove a good backup early).
- **Agent killed by the watchdog after the Beta 1.0 "fix".** Two causes, both
  reproduced on a copy of a 2.5 GB production database:
  - the daily backup and the full integrity check ran on the shared SQLite
    connection and held its lock for the whole copy/scan (integrity check alone:
    18.6 s with a warm cache), while the watchdog ping waits on that lock. The
    agent restarted, the backup was still due, and the cycle repeated until
    systemd gave up. Both now use a separate read-only connection; the probe
    wait dropped from 18.1 s to 0 ms on the same database. The full integrity
    check now runs at most once a day instead of on every maintenance pass.
  - `Type=simple` counted `WatchdogSec` from process start, so a cold start
    longer than 90 s was killed before it logged anything. The unit is now
    `Type=notify` with `TimeoutStartSec=300`; `READY=1` is sent only after the
    store answers. `WatchdogSec=90` is unchanged.
- **Size cap deleted real events to make room for orphaned graph edges.** The
  evidence graph was ~1.6 GB of a 2 GB cap, and ~90 % of scanned edges had no
  surviving evidence, yet each pass deleted 50,000 events first. The size cap
  now prunes orphaned graph data before trimming any event.
- **Backups were never pruned** (85 GB on the developer's machine). The agent
  now keeps the newest `SHIELD_BACKUP_KEEP` (default 3) daily and pre-upgrade
  backups and removes temporary files left by an interrupted backup.
  Pre-migration backups are kept.
- **Desktop notifications never arrived.** The root agent switched user with
  `setpriv`, which its own hardening blocks (`setresuid failed: Operation not
  permitted` on every attempt). Notifications now go over IPC to the new
  `shield-notify` user service, which also warns when the agent is unreachable
  for two minutes.
- Mixed IPv4/IPv6 authorised ranges made `scan_authorized_range` raise
  `TypeError`; the live evidence feed task was not tracked for shutdown;
  `pin_gateway_arp`, evasion and router polling passed `None` as an interface
  when none could be detected.
- Packet ingest hardening, bounded notifier delivery and test fixture cleanup
  from the 2026-09-11 audit.

### Quality

- ruff: 51 findings → 0. mypy: 136 errors → 0.

### Documentation corrections

- Removed or corrected statements that the code or evidence did not support:
  the watchdog "fixed and verified" claim, "ten" report sections (there are
  eleven), the "58 rule identifiers" count (no reproducible count exists),
  "roughly a millisecond" (never benchmarked), "all data stays on the machine"
  (optional Telegram), and "restricted capabilities" for the agent.

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
- Detection rules spanning authentication attacks,
  reconnaissance, malware-execution behaviour chains, network tampering
  (ARP, DNS, DHCP, ICMP redirect), device inventory, file and configuration
  tampering, risky service exposure, and Shield's own integrity.
- Correlation of related alerts into incidents, including multi-step chains.

### Evidence and investigation

- Evidence graph with 12 entity types and 11 relations, enforcing that no edge
  exists without a valid evidence reference.
- Expert Evidence: a read-only query surface over the event store, with hard
  row limits, timeouts, redaction, and an audit trail.
- Deterministic incident reports: eleven fixed sections — nine built only from
  measured data, each carrying an explicit epistemic state, and two reserved
  model prose slots that are unused.
- Guided incident Q&A: five closed questions — summarise, explain evidence, how
  certain, related process, what to inspect next — answered deterministically
  from the report without a model. Questions outside the set, and
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

- Monitoring data stays on the machine by default. No cloud service, no
  telemetry upload, no remote AI. Optional Telegram notifications, when an
  administrator configures them, send redacted alert text; see
  `docs/PRIVACY.md`.
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
  was addressed in this release. *Correction (2026-09-27): the fix was not
  sufficient; see Unreleased.*
- No language model is used by any feature. The isolated worker infrastructure
  is present but dormant; see the release notes for why.
