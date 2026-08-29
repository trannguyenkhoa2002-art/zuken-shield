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

Worth visiting first:

- **Overview** — what Shield is seeing right now.
- **Alerts** — individual detections.
- **Incidents** — grouped alerts, with the deterministic report.
- **Evidence** — the Expert Evidence viewer.
- **Health** — collector status and coverage.

## 4. Generate something to look at

Safe, on your own machine:

```bash
sudo cp /etc/hosts /etc/hosts.backup
echo "# shield quick start $(date +%s)" | sudo tee -a /etc/hosts
sudo mv /etc/hosts.backup /etc/hosts
```

Within a short time a `FILE_INTEGRITY_CHANGED` alert should appear.

## 5. Read an incident report

Open **Incidents** and select one. The report has ten sections built only from
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

Vietnamese and English are both available in Settings.

## Next steps

- `TESTING_GUIDE.md` — check Shield sees what it claims, in a lab you own.
- `DEMO_SCENARIOS.md` — end-to-end walkthroughs.
- `USER_GUIDE.md` — the long-form manual.
- `SECURITY_MODEL.md` — what runs as root, and why.
