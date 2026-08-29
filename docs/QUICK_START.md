# Quick Start

Ten minutes from installed to reading your first incident report.

## 1. Confirm the agent is running

```bash
systemctl is-active shield-agent
```

Expect `active`. If not, `journalctl -u shield-agent -n 50` will say why.

## 2. Watch it work

```bash
journalctl -u shield-agent -f
```

Within a minute or so you should see collectors reporting: device discovery,
connection watching, file-integrity baselines. Leave this running in a terminal
while you try the next step.

## 3. Open the interface

```bash
shield
```

The launcher starts the desktop interface with the group membership it needs.
You do not run a second agent — the interface talks to the service already
running.

The interface groups its screens into four sections. Worth visiting first:

- **Operations → Overview** — what Shield is seeing right now.
- **Operations → Alerts** — individual detections.
- **Operations → Incidents** — grouped alerts, with the deterministic report
  and the guided Q&A below it.
- **Investigation → Expert Evidence** — the bounded, audited read path.
- **Investigation → Security Center** — collector health, ATT&CK coverage, and
  Shield's own health.

If you were added to the `shield` group by the package install, `shield` works
straight away — the launcher starts the interface under that group, so you do
not have to log out and back in.

## 4. Generate something to look at

Safe, on your own machine:

```bash
sudo cp /etc/hosts /etc/hosts.backup
echo "# shield quick start $(date +%s)" | sudo tee -a /etc/hosts
sudo mv /etc/hosts.backup /etc/hosts
```

Within a short time a `FILE_INTEGRITY_CHANGED` alert should appear.

## 5. Read an incident report

Open **Operations → Incidents** and select one. The report has ten sections built only from
measured data: what type of incident, how severe, when, which asset, what was
observed, which facts are established, which evidence supports it, which
detections contributed, what to inspect next, and what the report cannot
establish.

Every evidence reference is clickable and opens the underlying event.

## 6. Ask about the incident

Under the report, "Ask about this incident" offers five questions:

- Summarise
- Explain evidence
- How certain?
- Related process
- What to inspect next?

Answers appear immediately. They are built from the same measured data as the
report — no model is involved, and none is required. Questions outside the set,
and requests to take action, are refused.

## 7. Change the language

Vietnamese and English are both available in **Management → Settings**.

## What needs what

- `sudo` — only for step 4's file change and for `apt install`; the interface
  itself must **not** be run with `sudo`.
- **Ubuntu 26.04 LTS or newer** — required for the packaged install, because
  `python3-pyside6.*` first appears there.
- **`bpftrace`** — optional. Without it, process, file and socket telemetry is
  reduced and Shield reports the reduced coverage.
- **`nftables`** — optional, and only needed for response actions that change
  the firewall.
- **`shield-packet-collector`** — optional. Without it, ARP/DHCP/ICMP/NDP
  observation, TCP-handshake visibility, outbound DNS observation and the live
  traffic graph are reported as unavailable; everything in this guide still
  works.

## Next steps

- `TESTING_GUIDE.md` — check Shield sees what it claims, in a lab you own.
- `DEMO_SCENARIOS.md` — end-to-end walkthroughs.
- `USER_GUIDE.md` — the long-form manual.
- `SECURITY_MODEL.md` — what runs as root, and why.
