# Zuken Shield — User and Operations Guide

**Created by Zuken** · Version `3.0.0a2` · [Bản tiếng Việt](HUONG_DAN_SU_DUNG.md)

This is the complete guide: what Shield does, how to install and run it, how to
work an alert, how to operate it in production, and how to test it before a
release. Start at [§3 Installation](#3-installation) if you just want it running.

---

## 1. What Shield is for

Shield defends a Linux endpoint and the local network around it. It collects
endpoint, LAN and system-log signals; detects noteworthy behavior; stores evidence
locally; and supports investigation, reporting and controlled response.

It detects and monitors:

- new devices on the LAN, gateway MAC changes, ARP/NDP conflicts, rogue DHCP, port scans;
- failed SSH logins, failed `sudo`, new USB devices, promiscuous mode;
- processes, systemd services, listening sockets, and changes to important files;
- DNS resolvers, `/etc/hosts` entries, open ports and service banners.

It supports the work after detection: incident grouping, deterministic risk
scoring, MITRE ATT&CK mapping, investigation cases, TXT/PDF reports, offline
summaries, and response actions (block IP/MAC, terminate a process, quarantine a
file) with validation and rollback.

**Shield is not** a complete antivirus, an enterprise SIEM/EDR, or a vulnerability
scanner. A risk score prioritizes investigation. It does not prove a host is safe,
and it does not prove a host is compromised.

**Only scan systems and networks you own or are authorized to test.**

---

## 2. Architecture and privileges

| Component | Runs as | Responsibility |
|---|---|---|
| `shield-agent` | root | Collection, detection, scoring, policy, storage, IPC server |
| `shield-privileged` | root | Minimal RPC surface for firewall and process response |
| `shield` (UI) | normal user | PySide6 interface over a local Unix socket |

The agent needs root for packet capture, selected logs and system response.
**Do not launch the UI with `sudo`.** Installation adds the desktop user to the
`shield` group, which grants access to `/run/shield/shield.sock`.

The pipeline separates description from judgment from action:

```text
collector ──> Event ──> detector ──> Alert ──> scorer ──> policy ──> store / IPC
                                                            │
                                                    response adapter
```

Collectors state facts. Detectors produce alerts with evidence and a playbook.
The scorer assigns 0–100 plus confidence. The policy engine is the only place an
automatic response can be decided, and it defaults to `audit_only=True` — every
outcome is `alert`, even at score 100. Every decision lands in `audit_log`.

Automatic containment requires three things at once: an administrator disabling
audit-only, a score at or above the threshold, and the exact rule in an allowlist.

---

## 3. Installation

### Install the package

```bash
cd ~/Desktop/"zuken shield"
sudo apt install ./dist/shield-monitor_3.0.0a2_amd64.deb
```

APT may need Internet access for missing system dependencies. Shield's own Python
code installs offline into `/opt/shield/.venv` and never touches PyPI.

### Build it yourself

```bash
./packaging/build-deb.sh
sudo apt install ./dist/shield-monitor_3.0.0a2_amd64.deb
```

Rebuilding without a version bump needs `--reinstall`:

```bash
sudo apt install --reinstall ./dist/shield-monitor_3.0.0a2_amd64.deb
```

### Verify

```bash
dpkg-query -W -f='${Status} ${Version}\n' shield-monitor
systemctl status shield-agent shield-privileged --no-pager
journalctl -u shield-agent -n 50 --no-pager
```

Expect `install ok installed 3.0.0a2`, both services `active`, and startup lines
naming the collectors, database path and IPC socket. The installer runs its own
health check and exits non-zero with logs if the services do not come up.

---

## 4. First run

Open **Shield** from the application menu, or run `shield`.

If the services are stopped, the launcher requests desktop authentication to start
them. It can also launch the UI with the newly assigned `shield` group, but logging
out and back in remains the reliable way to refresh group membership.

Recommended sequence:

1. Confirm the header shows **Agent online**.
2. **Management → Settings**: choose language and appearance.
3. Accept the proposed gateway baseline **only** on a trusted network, after you
   recognize the router IP and MAC.
4. **Monitoring → Devices**: run a quick scan, mark only devices you recognize as
   trusted.
5. Work from **Operations → Overview / Incidents**.

---

## 4b. Pausing and shutting down from inside the app

The title bar always carries a control group next to the connection indicator:

```
[● Monitoring]   [Pause ▾]   [Shut down Shield]
```

No `systemctl` required.

### When to use it

Shield runs `arp-scan` every 60 seconds and `nmap -sn` every 15 minutes. On a
home network that is harmless. On a **school, workplace, hotel or cafe
network**, their NAC/IDS flags it as unauthorised scanning — which may breach
that network's acceptable-use policy.

Before joining such a network, choose **Pause → Pause active scanning only**.

### Three levels

| Level | What stops | What remains |
|---|---|---|
| **Active scanning only** | arp-scan, nmap, self-audit, router polling, evasion | Still detects attacks through sniffing and host logs |
| **All monitoring** | also sniffing, capture, tarpit, log intake | Nothing |
| **Shut down Shield** | the agent exits | Nothing restarts until you start it again |

Prefer the first level. It removes exactly the part that causes trouble while
keeping detection alive — pausing the passive side blinds you for no benefit.

### Duration

Choose 15 minutes / 1 hour / 8 hours / until you resume. Timed pauses **resume
themselves**, so you cannot pause on arrival at school, forget, and leave the
machine unprotected at home.

Every pause and shutdown is written to the audit log. That record is what lets
Guardian tell "the operator stopped it" apart from "someone killed it".

## 5. Interface map

| Section | Page | Purpose |
|---|---|---|
| **Operations** | Overview | Posture, device and alert counts, active blocks |
| | Incidents | Related findings grouped by subject over 24 hours |
| | Alerts | Evidence, playbooks and response for individual alerts |
| **Monitoring** | Devices | LAN discovery, trust state, watching, self-audit shortcuts |
| | Traffic | Per-device traffic, protocols, router backends |
| | System Log | Filtered local-system events |
| | DNS Control | Resolvers, baseline, `/etc/hosts`, hijack testing |
| | WiFi Passwords | NetworkManager secrets already saved on this endpoint |
| **Investigation** | Security Center | Collector health, MITRE, timeline, cases, baseline, suppressions, fleet |
| | Response | The response queue: what Shield intends to do, has done, or has rolled back |
| | Assessment | Safe simulated-event validation of the detection pipeline |
| | Self-Audit | `nmap -sV`, port classification, snapshot comparison |
| | Reports | Period summaries, TXT/PDF export |
| **Management** | Settings | Language, theme, schedules, authorized ranges, blocks, evasion, tarpit, log export |
| | Help | Concise in-application guidance |

Gray is informational, yellow needs review, red needs prompt investigation.
Severity and risk are separate: severity is the rule's classification, risk
combines it with the evidence actually available.

---

## 6. Working an alert

1. Open **Incidents** and look for subjects with several related signals.
2. Open **Alerts**: read the rule, timestamp, subject, risk score and evidence.
3. Consider legitimate causes first — changing Wi-Fi, installing software, a new
   USB device, a VPN or Docker all generate signals.
4. Run a playbook only after verifying the exact IP, MAC, PID or file.
5. For endpoint response, read the preview, then confirm.
6. Create a case in **Security Center**, add notes, and move it through `open`,
   `investigating`, `resolved` or `false_positive`.
7. For recurring false positives, add a time-limited suppression with a reason.

Safety properties worth knowing:

- Firewall blocks expire automatically after 24 hours.
- Process termination checks PID **and** start ticks, so a reused PID is not hit.
- Quarantine verifies SHA-256, works across filesystems, creates a rollback ID,
  and refuses to overwrite a new file at the original path.
- Response uses preview → confirmation → a single-use token bound to the client
  that asked for it.

---

## 7. Devices, scans and Self-Audit

**Quick scan** uses `arp-scan` and suits routine checks. **Deep scan** uses
`nmap -sn`: more complete, several minutes.

Every observed device gets an internal `DEVICE-…` identity — an IP is not identity
because DHCP reassigns it. The Devices page shows likely type, confidence, risk,
current IP/MAC, observation history and **Why Shield thinks this**. When signals
are insufficient Shield keeps the type **Unknown** rather than guessing.

You can rename a device and add owner label, location, purpose and criticality.
Shield does not infer a person's identity. Different MACs merge only with your
confirmation, and **Split MAC** reverses an incorrect link.

**Authorized ranges**: in Settings, add a CIDR together with the authorization
reason. Shield scans saved ranges only, limits range size, and re-validates the
target inside the agent before scanning.

**Self-Audit** runs `nmap -sV` for service banners. It does not exploit or
brute-force anything. Results are Danger/Review/Normal. The CVE list is a small
offline hint set, not version-aware vulnerability scanning. Each scan becomes a
snapshot, so the next one can report newly opened or closed ports.

---

## 8. DNS, traffic and Wi-Fi

**DNS Control** reads real resolvers via `resolvectl` (falling back to
`/etc/resolv.conf`), watches UDP/53 traffic to unexpected resolvers, and lists
noteworthy `/etc/hosts` entries. After legitimately changing networks, review and
update the baseline. The hijack test needs `dig` (`sudo apt install dnsutils`).
DoT/DoH is not decrypted, and differing answers from public resolvers are often
just a CDN — not evidence of an attack.

**Traffic**: choosing **Watch** counts a device's traffic, and `tshark` adds
protocol classification (`sudo apt install tshark`). A host on a switched network
cannot see everyone else's traffic; for network-wide counters, configure the
router SSH backend or a custom script that prints:

```json
[{"ip":"192.168.1.23","mac":"aa:bb:cc:dd:ee:ff","rx_bytes":10485760,"tx_bytes":2097152}]
```

**WiFi Passwords** only reads networks NetworkManager already saved on this
machine. Passwords stay masked until revealed, and the reply goes only to the UI
client that asked. Shield does not capture handshakes or crack other networks.

---

## 9. Security Center and Assessment

In **Security Center**: check Collector Health before trusting data completeness;
search by PID, hash, IP, user, hostname or path to build a timeline and process
graph; treat MITRE coverage as *techniques observed*, not a safety percentage;
manage cases, the behavior baseline, suppressions and fleet endpoints; and keep
**Observed** data distinct from **Synthetic** Assessment data.

Kernel telemetry reports its backend as eBPF, auditd or procfs. With kernel BTF
and `bpftrace` present the agent runs a fixed exec-trace program — no probe text
ever comes from IPC or configuration. Missing eBPF is shown, never hidden.

The local anomaly baseline learns process, listener, service and DNS behavior for
a bounded period, then proposes explainable findings for new behavior. Synthetic
events never train it. Reset is explicit, confirmed and recorded. Nothing is
uploaded.

**Assessment** emits in-memory simulated events to validate
Event → Detection → Risk → Evidence. It does not exploit, block or modify the
system. Headless:

```bash
shield-assess run --output ./shield-assessment-output
```

It writes `assessment.json`, `junit.xml`, `results.sarif`, `coverage.json` and
`evidence.zip`. `--hmac-key-file` on `run` and `verify` gives authenticated
evidence. Custom profiles must declare `schema_version: 1` and
`authorized_local_only: true`; events are allowlisted and each test has a
60-second watchdog.

This suite proves the pipeline is wired correctly. It does **not** prove a kernel,
audit or network collector observes real activity — that needs the VM gates in §13.

---

## 10. Reports, data and backup

**Reports** summarizes today, 7 days or 30 days. TXT suits quick review and
scripts; PDF suits records and includes summary, timeline and evidence.
**Analyze locally** runs offline, sends nothing to the Internet, and holds no
response permissions.

| Data | Path |
|---|---|
| Database | `/var/lib/shield/shield.db` |
| Backups | `/var/lib/shield/backups/` |
| PCAP | `/var/lib/shield/pcaps/` |
| Snapshots | `/var/lib/shield/snapshots/` |
| Quarantine | `/var/lib/shield/quarantine/` |
| Installed code | `/opt/shield/` |
| Service logs | systemd journal |

**Management → Settings → Backup and recovery** controls daily automatic backups
(on by default); **Back up now** writes a consistent copy immediately. Package
upgrades always take a pre-upgrade backup regardless of that switch — that one is
a safety boundary, not a preference.

**Retention**: maintenance runs every six hours. Raw events older than 30 days,
alerts older than 365 days and expired intelligence cache entries are deleted.
The forensic ledger is never pruned automatically — archive and checkpoint it per
your retention policy before deleting anything by hand.

The ledger is hash-chained. It resists recomputation only when a separate HMAC
key is configured. Evidence stored on the same host is not immutable against an
attacker who already has root.

---

## 11. Tools that need care

**Pin gateway ARP** — only when the gateway baseline is known correct. It writes a
static neighbor entry; changing routers or networks can break connectivity until
that entry is removed or refreshed.

**Emergency evasion** — rotates the endpoint's MAC and requests a new IP on an
interval. Every rotation drops existing connections and can make managed Wi-Fi
reject the machine. It buys time; it does not remove an attacker. It never starts
by itself.

**Defensive tarpit** — opens decoy ports and holds connections that others
initiate. It never sends outbound floods. Limits protect you: 100 held connections
total, 10 per source IP (so one attacker cannot exhaust the pool), 30 minutes per
connection. Decoy ports bind `0.0.0.0` by default so a scanner is caught on any
interface; on a machine with a public address the agent warns, and you can set
`SHIELD_TARPIT_BIND` to a specific LAN address.

---

## 12. Operations and hardening

### Production checklist

1. Generate keys with `sudo ./scripts/generate-signing-keys.sh`, then set
   `SHIELD_AUDIT_HMAC_KEY` and `SHIELD_RULE_PUBLIC_KEY` through a systemd
   credential or secret manager. Do not commit them.
2. Keep `/var/lib/shield` owned by `root:shield`; database and quarantine files
   must not be world-readable.
3. Review FIM paths before deployment. Monitor specific security-sensitive files,
   not broad home or data trees.
4. Keep response policy in audit-only until previews and rollback have been tested
   on the target distribution.
5. Treat plugins as trusted code. Versioned permissions and isolated Python reduce
   mistakes but are not an OS sandbox.
6. Run `shield-benchmark --iterations 10` after installation and after adding large
   FIM paths. It exits non-zero when resource thresholds fail.
7. Check `systemctl status shield-agent`, journal errors and the forensic integrity
   tile after every upgrade.
8. For event-driven exec and protected-file telemetry, review and install
   `/usr/share/shield/audit/99-shield.rules` into `/etc/audit/rules.d/`. The
   `/proc` snapshot collector remains the fallback when auditd is unavailable.

### Trust boundary: the `shield` group

Anything that can connect to the agent socket (`/run/shield/shield.sock`, mode
`0660` `root:shield`) can send **every** allowlisted command, including
`response_execute` — which blocks IPs and terminates processes as root through the
privileged helper. There is no per-command role check on that socket.

**Adding a user to the `shield` group grants root-equivalent response capability.**
The installer adds the installing user automatically; on a multi-user machine,
review that membership.

To restrict further, set `SHIELD_IPC_ALLOWED_UIDS` to a comma-separated UID list in
`shield-agent.service`. Peers outside the list are then rejected at connect time
even if they are in the group; root is always allowed so the agent cannot lock
itself out. Unset means the historical group-based behavior.

The root helper is stricter: it accepts only root or the configured agent UID, its
vocabulary is a fixed allowlist, it runs no shell, and it parses no free-form
input. The UI never talks to it.

The socket path is validated at startup: the agent refuses to serve from a
directory it does not own or that is world-writable without a sticky bit, and it
never falls back to `/tmp`. Outside systemd, set `SHIELD_SOCK` or
`XDG_RUNTIME_DIR` explicitly.

### Signature and HMAC enforcement

Rule-pack signing, config-manifest verification, plugin signing and the ledger
HMAC are **opt-in**. With none configured the agent runs fail-open and logs a
startup warning naming exactly what is missing.

```bash
sudo ./scripts/generate-signing-keys.sh          # writes to /etc/shield
```

The script creates Ed25519 keypairs (matching the `openssl pkeyutl -verify -rawin`
verification Shield uses), a 256-bit HMAC key, signs the bundled rule pack, and
prints the `Environment=` lines for the unit file. Move the `*-private.pem` files
to an offline signing host afterwards — the endpoint needs only public keys and
`.sig` files.

Re-sign `shield/rules/default.json` after every edit: once `SHIELD_RULE_PUBLIC_KEY`
is set, an unsigned or stale rule pack stops agent startup. That is fail-closed by
design.

### Performance

Event and alert buses are bounded (8192 and 2048 records); producers get
backpressure instead of unbounded RAM growth. Collectors must avoid unbounded
queues, unjustified polling intervals and synchronous network calls on the event
loop. Hashing is incremental, intelligence lookups are cached, and overload drops
low-priority telemetry before security alerts.

---

## 12b. New in 1.1

### Guardian — watching Shield from outside

`shield-guardian.timer` runs every 60 seconds as a **separate** process and checks:

- whether `shield-agent` is still running — if it was stopped with no
  authorised shutdown on record, it raises a `critical` alert
- whether the agent is restarting repeatedly (`Restart=` can hide a crash loop)
- whether the installed files changed
- whether the database is present and openable
- whether the forensic ledger shrank — it may only ever grow

Before 1.1, `tamper_monitor_loop` ran *inside* the agent, so `systemctl stop
shield-agent` removed the self-protection along with the thing it protected.
Guardian closes exactly that hole.

```bash
journalctl -u shield-guardian -f     # what it is reporting
shield-guardian --json               # run one pass and print the result
```

The agent also pings `WATCHDOG=1` to systemd (`WatchdogSec=90`), so an agent
that **hangs** — rather than dies — is detected and restarted too.

### Collecting logs from other machines

See `PROBE.md` in this documentation directory. In short:

- **Shield Probe** — a small agent (15 KB, stdlib only) installed on other
  Linux machines that ships their logs over mTLS. Read-only; it never accepts
  a command.
- **Syslog** — for routers, cameras and switches that cannot run anything.
  These cannot be authenticated, so such logs **never enter the forensic
  ledger**, **never reach critical severity**, and **never train the baseline**.

### Risk scoring with all five factors

```
Risk = Severity × Confidence × Asset Value × Repetition × Threat Context
```

Set device criticality on the Devices tab (`Critical` / `Important` /
`Normal` / `Low priority`) — it feeds the score directly. Every factor that
moved the score is listed in the alert's `risk_reasons`.

### Incidents

The Incidents tab gained a table at the top: incidents assembled by the
correlation engine, each carrying a risk score, MITRE techniques and one
concrete recommended action. Correlation rules live in
`shield/rules/correlation.json`, so adding a new attack chain no longer means
editing source code.

### Automatic database recovery

On finding a corrupt database, the agent moves it aside to
`shield.db.corrupt.<timestamp>` (**preserved as evidence, never deleted**),
rescues whatever is still readable into a fresh database, and keeps running —
instead of crash-looping and leaving the machine unmonitored.

### Isolation with a dead-man switch

Endpoint isolation names the services it will cut (SSH/DNS/Web/file
sharing/email) and **lifts itself** if the agent stops renewing it. Without
that switch the isolation command is refused outright — isolating a machine
and then losing the ability to un-isolate it is worse than the problem being
defended against.

Since 2.0 it also actually isolates the machine. It writes a real nftables
ruleset into its own `table inet shield_isolation`, then reads the ruleset back
from the kernel and checks that both hooks default to `drop`, that loopback is
still permitted, and that your management address is still accepted. Only if
all of that is true does the command report success. If verification fails, the
table is removed and you are told isolation did **not** happen.

Two consequences worth knowing before you press the button:

- **Established connections are cut.** Isolation does not accept
  `ct state established`, because letting existing connections continue would
  keep an attacker's session alive — the exact thing being cut. Your management
  session survives because the management address is allowed by address.
- **Nothing else in your firewall is touched.** Isolation lives in its own
  table, so lifting it cannot remove an IP block that is still in force, and
  `nft delete table inet shield_isolation` is a complete cleanup.

## 12c. New in 2.0

2.0 is about one idea: **Shield must never claim something it has not
verified.** Most of what follows exists because a previous version claimed
something it had not checked, and nobody noticed.

### Isolation that actually isolates

Endpoint isolation now writes a real nftables ruleset into its own
`table inet shield_isolation`, then **reads the ruleset back from the kernel**
and checks that both hooks default to `drop`, that loopback still works, and
that your management address is still accepted. Only then does it report
success, and only then does it arm the dead-man switch.

Before 2.0 it armed the switch and reported "isolated" without applying a single
firewall rule. You saw the words "isolated" while the machine was fully online —
and because you believed it, you stopped looking for another way.

Two things worth knowing before you press the button:

- **Established connections are cut.** Isolation deliberately does not accept
  `ct state established`: letting open connections continue keeps an attacker's
  session alive, which is exactly what needs cutting. Your management session
  survives because the management address is permitted by address.
- **Nothing else in your firewall is touched.** Isolation lives in its own
  table, so lifting it cannot remove an IP block that is still in force.

### The response queue

The new **Response** page shows every action Shield intends to take, has taken,
or has rolled back. Three blocks, deliberately kept apart:

| Block | What it is |
|---|---|
| Table | What is happening now |
| State history | Every transition, who caused it, and when |
| Post-verification evidence | What Shield **read back from the system** afterwards |

The third block is the important one. The first two only tell you what Shield
*thinks*. An action shows `Applied, not yet verified` until something has
actually read the system state back — and an unverified action does not mean it
succeeded, only that nobody has checked.

Actions carry a TTL and lift themselves. If a rollback fails you get a
`critical` alert immediately, because a failed rollback leaves a firewall rule
that nobody is going to remove.

Four actions are implemented, each with the full contract — preview, check
preconditions, apply, verify, roll back:

| Action | Level | What it does |
|---|---|---|
| `snapshot_state` | 1 | Records ARP, sockets and the whole firewall ruleset to a file. Run it *before* anything else — once you block, the evidence is gone. |
| `rate_limit_ip` | 2 | Slows one address to 50 packets/second instead of cutting it. If Shield guessed wrong, a real user there still works — slowly, not never. |
| `block_ip` | 2 | Drops all traffic to and from one address, with a TTL. |
| `isolate_endpoint` | 3 | Cuts everything except the management address. **Always requires a human** — a machine isolating itself because of an uncalibrated detector is a self-inflicted incident. |

`stop_process` deliberately has no adapter: it cannot be undone, and 2.0 does
not automate anything it cannot undo.

**Stop all response actions** is a checkbox on the same page. It blocks every
new action from being applied, and it deliberately does **not** block rollbacks
or crash recovery — a safety switch that also blocked the way out would freeze
every firewall rule in place, and the person pressing it to stop the damage
would cause more. Approved work stays queued and runs once you turn it off.

### Kernel telemetry: measured, not advertised

Shield used to claim eBPF gave it process, file and socket coverage simply
because `/sys/kernel/btf/vmlinux` existed. In reality the collector emitted only
`process_exec`, so the `exec → write → connect` behaviour chain was dead code on
every real machine — it had never fired once, and could not.

Now each probe is **attached to the kernel at startup** and only what attaches
counts. Security Center shows one health row per event kind plus a dedicated
`behavior_chain` row that says plainly whether the chain works or which link is
missing.

Two design notes you may notice in the data:

- `file_write` traces `openat` with write flags, not the `write` syscall. `write`
  fires on every log line — tens of thousands of events per second on an idle
  machine, drowning the bus for almost no signal.
- The behaviour chain only fires when the written file lands where droppers put
  payloads (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm`, `/root`). Without that
  condition every `apt upgrade` raised a critical alert.

### Evidence graph and investigation

Every event now carries a unique `event_id`, both an event time and an ingest
time, and its origin and trust. From those, Shield builds an **evidence graph**
over 12 entity types — processes, files, addresses, users, sessions, devices,
services and more — joined by 11 relations such as `ran_on`, `spawned`, `wrote`,
`connected_to` and `logged_into`.

The rule that makes the graph worth trusting: **an edge cannot exist without at
least one evidence reference**, and writing an edge whose evidence does not
exist is refused. When retention deletes an event, every edge that depended on
it is removed too — a claim you can no longer check must not keep looking like a
claim you can.

Edges keep the trust of the evidence that created them and never inherit trust
from the entities at either end. A forged syslog line mentioning a machine you
have observed locally is still a forged syslog line.

### AI analysis, and the switch that turns it off

The **Incidents** page has an analysis panel. On a default installation it runs
a deterministic local analyser: it counts and joins relations, and it cannot
reason about intent. There is no language model unless an administrator
configures one.

What the panel will never do:

- write the word **Confirmed**. Confirming is your job, after you have read the
  evidence. The analysis can only say `unconfirmed`, `supported`, `contradicted`
  or `insufficient evidence`.
- state a probability. A confidence label is `low`, `medium` or `high` — never a
  number that looks like a calibrated chance of being right.
- hide its own mistakes. If an analysis cites evidence that does not exist, you
  still see what it claimed, plus a red line saying the reference was invented.
  Deleting it would hide the most useful signal there is: an analyser that keeps
  inventing evidence is one you should turn off.

**Turn off all AI analysis** is a checkbox on that page. It blocks every tool
call from the analysis layer and changes nothing about detection, scoring or
response — if turning off the analysis also stopped detection, nobody would ever
dare use the switch. The setting survives a restart.

### Detector accuracy is measured, not guessed

Alerts used to show a `confidence` number that read like "90% likely to be
correct". It actually meant "this alert has five pieces of evidence". Those are
different questions and 2.0 keeps them apart:

- **Evidence strength** — how rich and independent the evidence is. Computed
  from the alert itself.
- **Detector precision** — how often this detector, at this version, has
  actually been right. It exists only once **a person** has labelled outcomes,
  and it stays *unknown* until there are at least 20 labels. Unknown is shown as
  unknown; it is not filled in with 0.5.

This has a direct consequence: **an uncalibrated detector is never allowed to
act automatically.** Letting a detector whose accuracy nobody has measured take
action on its own is gambling with someone else's system.

### Exporting logs to a folder you choose

**Settings → Export logs to your own folder** writes an extra copy of Shield's
logs wherever you point it, so you can archive them, hand them to someone, or
load them into your own tools. The primary copy stays in Shield's database.

You choose the maximum Shield may use. The page then tells you what actually
matters:

> Using 350.0 MB of 1.0 GB (34.2%) — 22 files
> At the current rate of about 80.0 MB per day, this quota holds roughly 12.8 days.
> 1.7 TB free on the disk.

"10 GB" tells you nothing; "roughly 12 days" tells you a great deal. There is
deliberately no *unlimited* option — an unlimited quota means Shield gives
itself permission to fill your disk.

Two safety rules worth knowing:

- Shield only ever counts and deletes files **it created** (`shield-log-*.jsonl`).
  Point it at your Documents folder and it will not touch anything else there.
- The folder must already exist and must not be a system directory, and no part
  of the path may be a symbolic link. Shield runs as root; following a symlink
  someone else planted is how a log exporter becomes a way to overwrite
  `/etc/shadow`.

### Threat intelligence that can be withdrawn

Threat intelligence is data **written by someone else** that Shield uses to make
decisions about your machine. That makes it an attack surface: one poisoned
record saying your gateway is a command-and-control server would have Shield
recommend blocking the thing keeping the machine online.

Every intelligence document Shield holds now records where it came from, its
content hash, whether its signature verified, when it was fetched, when it was
imported, and which trust tier it is in. Only a document with a **verified
signature** enters the trusted tier. Importing unsigned content is possible but
must be asked for explicitly, and it lands in the untrusted tier — where it is
shown to you but cannot decide a verdict.

A document with an *invalid* signature is refused by every tier. That is a
different thing from having no signature: it means somebody changed the content
after it was signed.

If a source turns out to be poisoned, **revoke it**. Revocation takes effect on
the next lookup — no restart. It does not delete the document, because after an
incident the question you need answered is "what was yesterday's conclusion
based on, and what happened to it?"

External intelligence only ever **corroborates**. No matter how many signed
sources agree, an assertion whose every piece of evidence is external is never
allowed to reach `supported`. External sources describe the world in general;
they did not observe your machine.

### The database size limit now actually limits

`SHIELD_DATABASE_MAX_MB` was measured against the file size. SQLite does not
shrink a database file when rows are deleted, so the limit never saw its own
deletions take effect: it would delete up to two million events and still report
being over the limit. It now measures the space actually in use, and new
installations reclaim disk automatically.

If you keep the 30-day retention, note that the evidence graph adds roughly
600 bytes per relevant event on top of the raw events. Raise the limit if you
want the full 30 days.

---

## 12d. New in 3.0. Local AI explanation, and why it is off

Shield 3.0 can add a short written explanation to an incident report. It is off
until you turn it on, it runs on this machine, and the report does not depend on
it.

### The report comes first, always

Opening an incident builds a deterministic report from what Shield measured:
incident type, severity, time window, affected asset, observed activity,
confirmed facts, validated evidence, supporting detections, recommended next
steps, and limitations. That report is the authority. It is complete on its own,
it renders in about a millisecond, and every value in it comes from the database
rather than from a model.

The AI explanation, when it exists, is a separate block below the report,
labelled, and visibly subordinate. Nothing in the report is written by a model,
and nothing a model writes is ever presented as a measurement.

### Two switches, and both must be on

An administrator configures a provider in the service unit. Then someone ticks
**AI explanation** on the Incidents page. Neither alone is enough. Configuring a
provider is installation; ticking the box is accepting that this machine will
run a model. If one action did both, the model would start running the moment
Shield was installed and nobody would ever have agreed to it.

The default is off. Turning it off later leaves the report exactly as complete
as it was.

### You provide the model

Shield never downloads a model. There is no HTTP client in the AI code and no
mirror to fetch from. You install a GGUF file yourself, root-owned and
world-readable, under `/opt/shield/models`. The tested build is
Qwen2.5-1.5B-Instruct Q4_K_M. The runtime, `llama-cpp-python`, is an optional
dependency that Shield does not need in order to start.

Install the runtime into the agent's own environment:

```bash
sudo /opt/shield/.venv/bin/pip install llama-cpp-python
```

That path matters. The model worker runs isolated (`python -I`) so that
untrusted native code cannot pick up whatever happens to be in your user or
system site-packages, which also means a runtime installed anywhere else is
invisible to it. If it is missing, the explanation panel reports the provider as
unavailable and the report is unaffected.

**Reinstall the runtime after every Shield upgrade.** The package rebuilds its
virtualenv from scratch on each install, deliberately: installs are offline and
reproducible, and nothing is carried over from the previous one. Your GGUF file
lives outside the virtualenv and survives; `llama-cpp-python` does not. Until
you reinstall it, Shield runs normally and the AI answer reports the provider as
unavailable.

With no model and no runtime installed, Shield runs normally and incident
reports work exactly as documented. The explanation simply never appears.

### It runs in the background, in its own cgroup

Inference takes roughly 15 to 25 seconds on the tested CPU, so it never happens
while you wait. Opening an incident returns the report immediately and queues
the explanation; the panel says it is being prepared, and the text appears when
it is ready.

The model runs in a separate process, in a transient systemd scope beside the
agent rather than inside it, capped at 2560 MB with swap disabled, 300% CPU and
96 tasks, with networking removed. If that scope cannot be created, or the
network cannot be taken away, no model runs at all and you get the deterministic
report. There is no unconfined fallback.

### Only scenarios that passed review

Eight of Shield's forty-five scenarios may be explained: the authentication
attack family, and suspicious execution chains. The rest are deterministic-only,
including everything Shield could not classify. Scenarios earn eligibility by
measurement, one family at a time, and a family that scored 94.7% against a 95%
bar was left off rather than rounded up.

Eligibility is decided by the agent. The interface cannot widen it.

### What it will not do

There is no chat, no command box, and no way to ask the model a question. The
model is never given tools, a database handle, or a capability token, and it
cannot trigger a response action. It receives facts that Shield already
validated and writes prose about them; that is the whole interface.

Every sentence is checked before it is stored. Prose that invents a port, an
address, a process id, a count, a timestamp, or an evidence reference is
discarded, as is prose that claims certainty Shield does not have. Discarding
happens per sentence, so a partly-wrong explanation loses the wrong part and
keeps the rest, and an explanation that loses everything is simply absent.

### Limitations worth knowing

The filter checks claims against measured values. It does not judge tone or
intent, so an explanation may contain instruction-like text such as "run
isolate_host now". Nothing executes it: Shield has no path from generated text
to an action, and the text appears only inside the labelled explanation block.
Treat it as commentary, not instruction, and act on the report.

An explanation is produced at most twice for the same evidence. If it fails
both times, the panel says so and stops trying. Changing the evidence, the
language, or the model produces a new question and a fresh attempt.

Explanations are not retained as raw model output. Only the validated sentences
are stored, and they are discarded when the evidence they describe changes.

---

## 13. Testing and release gates

Unit tests are unprivileged and safe on a workstation:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest tests/ -q
```

Privileged tests refuse to run unless explicitly enabled. Never run them on a
workstation carrying production traffic.

```bash
# nftables lifecycle inside a private network namespace
sudo SHIELD_RUN_ROOT_TESTS=1 ./scripts/security-integration.sh

# smoke test against an actually installed package
sudo SHIELD_RUN_VM_TESTS=1 ./scripts/vm-smoke.sh
```

The smoke test checks service state, systemd hardening flags, the startup log,
`shield-benchmark` thresholds, forensic-ledger verification against the real
database, and headless UI startup.

Release-lab results are evaluated with:

```bash
shield-admin release-gate ./advanced-lab-results.json
```

It exits 5 when a required scenario is missing or failed, and never runs
privileged tests itself — a release check must not alter a workstation.

### Still required before 1.0 Stable

1. Soak tests at 24h, 72h, 7d and 30d on the packaged build, with evidence kept.
2. Every root/real-response Release Lab scenario in a namespace or disposable VM,
   with rollback results recorded, across Ubuntu, Debian and Kali images.
3. An independent privilege-boundary review covering sockets, helper allowlists,
   TOCTOU, symlinks, package scripts and plugin trust.
4. Database restore and package rollback validated on every supported Ubuntu.
5. Production YARA execution and complete per-device time-series baselines
   (active hours, bandwidth, peers, destinations).
6. Dedicated DHCP, mDNS and SSDP/UPnP collectors for device profiling.
7. Persisted incident records with status, affected assets and evidence timeline.

Until those pass, the honest product name is **Zuken Shield 1.0 RC**.

---

## 14. Troubleshooting

**UI says the agent is offline**

```bash
groups "$USER"
systemctl status shield-agent --no-pager
ls -l /run/shield/shield.sock
journalctl -u shield-agent -e --no-pager
```

If `shield` is missing from your session's groups, log out and back in.

**`No module named shield`** — the private virtualenv did not finish installing:

```bash
sudo apt install --reinstall ./dist/shield-monitor_3.0.0a2_amd64.deb
/opt/shield/.venv/bin/python -c 'import shield; print(shield.__version__)'
```

**Installation incomplete or dependencies failed**

```bash
sudo apt install ./dist/shield-monitor_3.0.0a2_amd64.deb
sudo dpkg --configure -a
```

**A scan or optional feature does nothing** — check the journal for missing
`arp-scan`, `nmap`, `tcpdump`, `nftables` or permission errors. Install `tshark`
for protocol classification, `dnsutils` for the DNS test, `fonts-dejavu-core` if
Vietnamese glyphs are missing from PDFs. The Wi-Fi page is empty when
NetworkManager has no saved connections.

---

## 15. Uninstalling

```bash
sudo apt remove shield-monitor     # keeps /var/lib/shield
sudo apt purge shield-monitor      # also keeps investigation data
```

Delete `/var/lib/shield` by hand only after confirming you no longer need its
history, PCAPs, snapshots or quarantine.

---

## 16. Safety boundaries

- Scan only systems and networks you own or are authorized to test.
- Do not treat CVE hints, risk scores or MITRE coverage as proof of vulnerability.
- Verify evidence before blocking, terminating, quarantining or pinning ARP.
- Do not enable automatic response before testing preview and rollback in a VM.
- Plugins are trusted code; enable only reviewed ones and verify signatures.
- Shield does not replace backups, security updates, a managed firewall, MFA, or
  an incident-response process.
