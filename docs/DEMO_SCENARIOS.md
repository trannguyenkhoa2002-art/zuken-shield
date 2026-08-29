# Demonstration Scenarios

End-to-end walkthroughs: an action you take, and what Shield should show at each
stage — telemetry, alert, incident, evidence, report.

All scenarios are benign. None installs malware, exploits anything, or damages a
system. **Run them only on machines you own.**

Each scenario follows the same chain:

```
action ──► event ──► alert ──► incident ──► evidence ──► report ──► guided Q&A
```

---

## Scenario 1 — A monitored file changes

**Story.** Something edits a file that should not change quietly.

**Action**

```bash
sudo cp /etc/hosts /etc/hosts.demo-backup
echo "# demo $(date +%s)" | sudo tee -a /etc/hosts
```

**Telemetry** — a file-integrity check observes the content change.

**Alert** — `FILE_INTEGRITY_CHANGED`, naming the path.

**Evidence** — the event recording the change; a `file` entity in the graph.

**Report** — confirmed facts name the path; the epistemic state reflects how
much corroborating evidence exists.

**Guided Q&A** — *Explain evidence* names the validated references; *What to
inspect next* suggests capturing state.

**Cleanup**

```bash
sudo mv /etc/hosts.demo-backup /etc/hosts
```

---

## Scenario 2 — A new listening socket appears

**Story.** A service starts listening that was not listening before.

**Action**

```bash
python3 -m http.server 18080 &
sleep 30
kill %1
```

**Telemetry** — the socket inventory gains an entry with its owning process.

**Alert** — on a sensitive or remote-access port,
`ENDPOINT_SENSITIVE_LISTENER_OPENED` or
`ENDPOINT_LISTENER_ON_REMOTE_ACCESS_PORT`. Port 18080 is intentionally
unremarkable, so this scenario usually demonstrates *inventory* rather than an
alert — a useful reminder that visibility and alerting are different things.

**Evidence** — a `service` entity with a `listens_on` relation.

**Cleanup** — the `kill` above.

---

## Scenario 3 — Repeated failed logins

**Story.** Someone guesses a password from another machine in your lab.

**Prerequisites** — SSH on Machine A; Machine B is yours.

**Action** — from Machine B, fail to authenticate four or five times:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    demo@<machine-a-address>
```

**Telemetry** — authentication failures ingested from the journal.

**Alert** — `SSH_AUTH_FAILURE_OBSERVED` per failure, then
`LOCAL_SSH_BRUTEFORCE` once the threshold is crossed.

**Incident** — repeated failures accumulate into `ACCUMULATED_AUTH_FAILURES`.

**Report** — an authentication-attack scenario naming the source address and the
failure count, both taken from the stored events.

**Guided Q&A** — *How certain* preserves the uncertainty: repeated failures are
not proof of compromise, and the answer says so.

---

## Scenario 4 — A benign port scan

**Story.** A host on the lab network enumerates your ports.

**Prerequisites** — **both machines yours.**

**Action** — from Machine B:

```bash
nmap -sT -p 1-1000 <machine-a-address>
```

**Telemetry** — connection attempts across many ports from one source.

**Alert** — `SCAN_PORTSCAN`, recording the observed scan type (`connect` versus
`syn`) from the packets themselves rather than assuming.

**Evidence** — the source address and the ports touched.

**Report** — a reconnaissance scenario. Note that reconnaissance is
deterministic-report-only by design.

---

## Scenario 5 — A suspicious execution chain, built from harmless parts

**Story.** The behaviour pattern that matters most: a process runs, writes
files, then opens an outbound connection. Nothing here is malicious — that is
the point. The *shape* is what Shield detects.

**Prerequisites** — `bpftrace` installed.

**Action** — on Machine A:

```bash
cat > /tmp/demo-chain.sh <<'SH'
#!/bin/bash
for i in 1 2 3; do echo "demo $i" > /dev/shm/demo-artifact-$i.txt; done
curl -s --max-time 3 http://<machine-b-address>:18080/ >/dev/null || true
SH
chmod +x /tmp/demo-chain.sh
/tmp/demo-chain.sh
```

**Telemetry** — `process_exec`, several `file_write`, then `socket_connect`,
all attributed to one process tree.

**Alert** — `BEHAVIOR_EXEC_WRITE_CONNECT`.

**Incident** — scenario `SUSPICIOUS_EXECUTION_CHAIN`, family
`MALWARE_EXECUTION`. The family name describes the *pattern class*, not a
verdict: a legitimate installer looks similar, which is exactly why the report
states what is established and what is not.

**Evidence** — the process identity, the sequence of markers, and the paths
written, each backed by a stored event.

**Report** — the ten sections, with the process identity rendered exactly as
recorded.

**Guided Q&A**

- *Summarise* — the scenario name, the asset, the established facts.
- *Related process* — the exact process identity.
- *How certain* — unconfirmed, with the limitations listed.
- *What to inspect next* — the recommended step, stated as advice Shield will
  not perform for you.

**Cleanup**

```bash
rm -f /tmp/demo-chain.sh /dev/shm/demo-artifact-*.txt
```

---

## Scenario 6 — A USB device is attached

**Action** — attach a USB stick to Machine A, wait, remove it.

**Alert** — `ENDPOINT_USB_ADDED`, plus `ENDPOINT_USB_STORAGE_ATTACHED` for
storage.

**Evidence** — a device entity with vendor and product identifiers.

---

## Scenario 7 — The resolver changes

**Story.** DNS is redirected — a classic precursor worth noticing.

> Only on a network you control.

**Action** — change the system resolver on Machine A, wait, change it back.

**Alert** — `DNS_RESOLVER_CHANGED`, and possibly `DNS_UNEXPECTED_SERVER`.

**Correlated incident** — combined with ARP anomalies, this can raise
`CORRELATED_MITM_AND_DNS_CHANGE`.

**Cleanup** — restore the original configuration.

---

## Scenario 8 — Shield notices its own trouble

**Story.** A monitoring tool that cannot report its own failure is worse than
none.

**Action**

```bash
sudo systemctl stop shield-agent
sleep 60
sudo systemctl start shield-agent
```

**Alert** — the guardian raises `GUARDIAN_AGENT_STOPPED_BY_OPERATOR`, which is
deliberately distinct from an unexplained stop.

**Evidence** — the stop is recorded with its cause, so a deliberate maintenance
window does not read the same as a tampering event.

---

## Reading these honestly

- A scenario producing **no** alert is still information. Conservative detectors
  are a design choice, not a defect.
- Family names such as `MALWARE_EXECUTION` describe a **pattern class**. The
  report's epistemic state is where the verdict lives, and for these scenarios
  it will usually say the cause is not established.
- The evidence is the authority. If a report and the events disagree, the events
  win, and that disagreement is a bug worth reporting.
