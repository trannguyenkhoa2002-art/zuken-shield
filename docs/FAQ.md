# Frequently Asked Questions

### Is Shield an AI product?

No. Beta 1.0 does not use a language model for anything. Detection, correlation,
reporting, and the guided Q&A are all deterministic. The repository contains
isolated infrastructure for running a local model, but it is dormant — no
feature starts it.

### Then why is the AI code there at all?

Because a model was evaluated for one feature — the incident summary — and it
failed. It truncated a process identifier in every attempt, and when the
identifier was withheld it mislabelled the incident type. The infrastructure was
kept, with the isolation and validation that made the failure safe, so a better
model can be evaluated later. The measurements are in the release notes.

### Does Shield send anything to the internet?

No. There is no cloud service, no telemetry upload, and no remote AI. Data stays
in `/var/lib/shield`. Shield does query the local network it is monitoring, and
it can perform DNS lookups as part of monitoring.

### Does it need root?

The agent does, for kernel telemetry and packet capture. The desktop interface
runs as your normal user and talks to the agent over a Unix socket. Actions that
change system state go through a separate privileged helper with a fixed
operation set, so the agent never runs arbitrary commands.

### Will it slow my machine down?

The agent is capped at 1 GiB of memory by its systemd unit and typically uses a
few hundred megabytes. Housekeeping is bounded per pass so it cannot monopolise
the database.

### Does it work without bpftrace?

Yes, with reduced endpoint visibility. Shield measures which kernel probes
attached and reports the coverage it actually has rather than assuming.

### Can it protect a whole network?

No. Shield monitors one host and observes the local network around it. It is not
a fleet product and has no central console.

### Can I use it on my company network?

Only with authorisation. Shield observes network traffic and discovers devices;
doing that without permission is unlawful in many places. See `DISCLAIMER.md`.

### Will it remove malware?

No. Shield observes, correlates, and preserves evidence. It can take limited
reversible actions such as blocking an address, but it is not antivirus.

### Why are some incidents "deterministic report only"?

Because their evidence shape has not been validated well enough to say more.
Shield prefers a shorter honest report over a longer speculative one.

### What does "epistemic state" mean in a report?

How certain Shield is: confirmed fact, supported hypothesis, unconfirmed, or
insufficient evidence. It is derived from the number of validated evidence
references and the status assigned by the evidence validator — never guessed.

### An alert looks wrong. What should I do?

Open the evidence behind it. The stored event is the authority. If the evidence
does not support the alert, that is a bug worth reporting with the rule
identifier and a redacted excerpt.

### Nothing is alerting. Is it broken?

Possibly not. Several detectors are deliberately conservative, and a quiet
network is quiet. Check the health view to confirm collectors are reporting, and
use `TESTING_GUIDE.md` to generate a known-good event.

### Which languages does the interface support?

Vietnamese and English.

### Is it production ready?

No. It is a beta without an independent security review or completed soak
testing. Use it in a lab, or on a machine where you understand the risk.
