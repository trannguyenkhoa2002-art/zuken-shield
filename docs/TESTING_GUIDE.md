# Testing Guide

How to check that Zuken Shield actually sees what it claims to see, using a lab
you own and benign actions only.

> **Authorised systems only.** Every procedure here runs against your own
> machines. Generating traffic toward hosts you do not control is unlawful in
> many jurisdictions, and nothing in this guide requires it.

Nothing below installs malware, exploits a vulnerability, or damages a system.
Where a test needs "suspicious" behaviour, it is produced with ordinary tools
doing ordinary things in an unusual order — which is exactly what the detection
logic looks for.

---

## Lab topology

The minimum useful lab is two machines on a network segment you control.

```
        ┌──────────────────────────┐
        │  Machine A               │
        │  Shield host             │   monitored Linux endpoint
        │  - shield-agent (root)   │   runs the agent + interface
        │  - shield UI             │
        └────────────┬─────────────┘
                     │  isolated LAN / lab VLAN / host-only network
        ┌────────────┴─────────────┐
        │  Machine B               │
        │  Test workstation        │   generates authorised test activity
        │  (any OS with ssh, nmap) │
        └──────────────────────────┘

        Optional: a router or virtual network you own, for the
        ARP / DHCP / DNS observation tests.
```

Both machines can be virtual. A host-only or internal virtual network is the
safest choice, because nothing you generate can leave it.

If you only have one machine, tests 1–6 and 10–15 still work. Tests 7 and 9 need
a second host.

## Before you start

```bash
systemctl is-active shield-agent          # expect: active
journalctl -u shield-agent -f             # leave this running in a terminal
```

Most tests follow the same rhythm: perform an action, watch the journal, then
open the interface and confirm the alert, the incident, and the evidence.

---

## 1. Service health

**Purpose** — confirm Shield is running and self-reporting before you trust any
other result.

**Action**

```bash
systemctl status shield-agent shield-privileged
systemctl show shield-agent -p NRestarts -p Result -p MemoryCurrent
```

**Expected** — both active; `Result=success`; `NRestarts` stable across a few
minutes. In the interface, the health view shows collectors reporting recently.

**Expected evidence** — startup lines in the journal listing which collectors
started and which kernel probes attached.

**Cleanup** — none.

---

## 2. File change detection

**Purpose** — confirm file-integrity monitoring observes a change to a monitored
path.

**Prerequisites** — know which paths are monitored; the packaged unit monitors
`/etc/hosts`, `/etc/passwd`, and `/etc/sudoers` by default.

**Action**

```bash
sudo cp /etc/hosts /etc/hosts.lab-backup
echo "# shield lab test $(date +%s)" | sudo tee -a /etc/hosts
```

**Expected observation** — a `FILE_INTEGRITY_CHANGED` alert naming the path.

**Expected evidence** — an event recording the change, with the file entity in
the evidence graph.

**Expected report** — opening the incident gives a report whose confirmed facts
name the path.

**Cleanup**

```bash
sudo mv /etc/hosts.lab-backup /etc/hosts
```

---

## 3. Process execution visibility

**Purpose** — confirm the kernel telemetry path reports process execution.

**Prerequisites** — `bpftrace` installed; without it this test will correctly
show reduced coverage instead of events.

**Action**

```bash
/usr/bin/uptime
/usr/bin/id
```

**Expected observation** — `process_exec` events in the event stream. A first
sighting of an unusual binary may raise `ANOMALY_NEW_BEHAVIOR`.

**Expected evidence** — process entities with parent/child relations.

**Cleanup** — none.

---

## 4. Listening port visibility

**Purpose** — confirm Shield notices a new listening socket.

**Action**

```bash
python3 -m http.server 18080 &
sleep 20
kill %1
```

**Expected observation** — the listener appears in the socket inventory. On a
sensitive port, `ENDPOINT_SENSITIVE_LISTENER_OPENED` may fire; port 18080 is
deliberately unremarkable, so the inventory is the thing to check.

**Cleanup** — the `kill` above.

---

## 5. Network connection visibility

**Purpose** — confirm outbound connections are observed and attributed.

**Action** — from Machine A, to a host you own:

```bash
curl -s --max-time 5 http://<machine-b-address>:18080/ >/dev/null
```

**Expected observation** — a `socket_connect` event, attributed to the process
that made it.

**Expected evidence** — a `connected_to` relation between the process and the
destination.

**Cleanup** — none.

---

## 6. Failed authentication telemetry

**Purpose** — confirm authentication failures are ingested and counted.

**Prerequisites** — an SSH server on Machine A; both machines yours.

**Action** — from Machine B, deliberately fail to log in a few times:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    labtest@<machine-a-address>
# enter a wrong password, three or four times
```

**Expected observation** — `SSH_AUTH_FAILURE_OBSERVED` per failure, and
`LOCAL_SSH_BRUTEFORCE` once the threshold is crossed. Repeated failures
accumulate into `ACCUMULATED_AUTH_FAILURES`.

**Expected report** — an authentication-attack scenario naming the source
address and the failure count.

**Cleanup** — none. Consider removing the lab account afterwards.

---

## 7. Port scan detection

**Purpose** — confirm scan detection fires on a real scan.

**Prerequisites** — **Machine B scanning Machine A, both yours.**

**Action** — from Machine B:

```bash
nmap -sT -p 1-1000 <machine-a-address>
```

**Expected observation** — `SCAN_PORTSCAN`, with the scan type recorded
(`connect` versus `syn`) based on observed packets rather than assumption.

**Expected evidence** — the ports involved and the source address.

**Cleanup** — none.

---

## 8. USB device events

**Purpose** — confirm removable-media events are captured.

**Action** — attach a USB stick to Machine A, wait, then remove it.

**Expected observation** — `ENDPOINT_USB_ADDED`, and
`ENDPOINT_USB_STORAGE_ATTACHED` for storage devices.

**Expected evidence** — a device entity with vendor and product identifiers.

**Cleanup** — unmount and remove.

---

## 9. Network anomaly observation

**Purpose** — confirm ARP and DNS observation work.

> Only on a network you control. These tests change local network state.

**Action (DNS)** — change the system resolver on Machine A, then change it back:

```bash
resolvectl dns          # note the current value first
# change the resolver through your normal configuration, wait, restore it
```

**Expected observation** — `DNS_RESOLVER_CHANGED`, and possibly
`DNS_UNEXPECTED_SERVER` when queries go somewhere unexpected.

**Action (ARP)** — reboot or reconnect the lab router so its MAC association is
re-observed.

**Expected observation** — gateway MAC changes raise `MITM_GATEWAY_MAC_CHANGED`;
conflicting ARP answers raise `MITM_ARP_CONFLICT`. Both are conservative by
design and may not fire on a quiet network — that is correct behaviour, not a
failure.

**Cleanup** — restore the original configuration.

---

## 10. Incident correlation

**Purpose** — confirm related alerts group into one incident rather than
appearing as unrelated noise.

**Action** — within a few minutes, on hosts you own: run test 7 (scan) and then
test 6 (failed logins) from the same Machine B.

**Expected observation** — beyond the individual alerts, a correlated incident
such as `CORRELATED_RECON_AND_SSH_ATTACK`.

**Expected report** — one incident listing both contributing rules with the
evidence from each.

**Cleanup** — none.

---

## 11. Evidence viewer validation

**Purpose** — confirm every evidence reference in a report actually resolves.

**Action** — open any incident, read the report, and click each evidence
reference.

**Expected** — every reference opens the Expert Evidence view showing the
underlying event. A reference that does not resolve is a bug worth reporting.

**Cleanup** — none.

---

## 12. Guided incident Q&A

**Purpose** — confirm the five closed questions answer from measured data.

**Action** — open an incident and use each quick action: summarise, explain
evidence, how certain, related process, what to inspect next. Then type a
question outside the set, such as "what's the weather?", and an action request,
such as "isolate host now".

**Expected**

- All five answer effectively immediately; no model runs and none is required.
- Identifiers in the answers match the report exactly.
- The out-of-scope question and the action request are both refused, and no
  action is taken.

**Cleanup** — none.

---

## 13. Response workflow

**Purpose** — confirm response actions verify and roll back.

> Do this in a disposable virtual machine. Response actions change host state.

**Action** — with response configured, trigger a low-level action such as
`snapshot_state` from the response view.

**Expected** — the action records preconditions, executes, verifies against
observable state, and reports the outcome. A failed verification rolls back and
raises `RESPONSE_VERIFICATION_FAILED` or `RESPONSE_ROLLBACK_FAILED`.

**Cleanup** — revert the virtual machine snapshot.

---

## 14. Maintenance and watchdog health

**Purpose** — confirm Shield stays responsive while housekeeping runs.

**Action**

```bash
journalctl -u shield-agent | grep "Database maintenance" | tail -5
systemctl show shield-agent -p NRestarts -p Result
```

**Expected** — maintenance lines showing bounded work per pass (`events_deleted`
and `graph_edges_scanned` capped, with `more_work` indicating whether a backlog
remains). No `Watchdog timeout` entries. `NRestarts` stable.

**Cleanup** — none.

---

## 15. Restart and upgrade resilience

**Purpose** — confirm an upgrade preserves evidence and restarts cleanly.

**Action**

```bash
sudo systemctl restart shield-agent
sleep 30
systemctl is-active shield-agent
sudo apt install -y --reinstall ./dist/shield-monitor_*_amd64.deb
```

**Expected** — the agent returns to active; the database passes its integrity
check; existing alerts and devices are still present; the schema gains new
tables additively without losing any.

**Note** — a package install rebuilds the agent's virtualenv from scratch on
purpose. If you had installed the optional `llama-cpp-python` runtime, reinstall
it afterwards. Nothing in Beta 1.0 needs it.

**Cleanup** — none.

---

## Reading the results honestly

- **No alert is a result too.** Several detectors are deliberately conservative.
  Confirm the collector is running before concluding a detection is broken.
- **Check coverage before blaming detection.** Without `bpftrace`, endpoint
  visibility is genuinely reduced, and Shield reports that rather than hiding it.
- **Evidence beats the alert.** If an alert looks wrong, open the evidence. The
  stored event is the authority.
