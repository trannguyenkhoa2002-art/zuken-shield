# Troubleshooting

## The agent will not start

```bash
systemctl status shield-agent
journalctl -u shield-agent -n 80 --no-pager
```

Common causes:

- **Database integrity check failed.** Shield refuses to open a damaged
  database rather than migrating it. The original is preserved and the journal
  names the problem. Restore from `/var/lib/shield/backups/`.
- **Port or socket already in use.** A previous instance may still be running:
  `systemctl stop shield-agent` and check for stray processes.
- **Permissions on `/var/lib/shield`.** The agent needs to own its data
  directory.

## The interface cannot reach the agent

```bash
groups | grep shield          # are you in the shield group?
ls -l /run/shield/shield.sock # does the socket exist?
```

The installer adds you to the `shield` group, but group membership only applies
after you log out and back in.

## No process, file, or connection events

Kernel telemetry needs `bpftrace`:

```bash
which bpftrace
journalctl -u shield-agent | grep -i probe
```

Shield reports which probes attached. If none did, endpoint visibility is
genuinely reduced — the health view shows the coverage it actually has rather
than claiming full coverage.

## No alerts at all

Not necessarily a fault. Several detectors are deliberately conservative and a
quiet network is quiet. Confirm collectors are reporting in the health view,
then generate a known-good event from `TESTING_GUIDE.md` — the file-change test
is the quickest.

## The agent was restarted by the watchdog

```bash
journalctl -u shield-agent | grep -E "Watchdog timeout|Failed with result"
```

The agent pings the systemd watchdog only when the event loop is running *and*
the database answers, so a ping failure is a real stall rather than a formality.
Database maintenance is bounded per pass specifically so it cannot cause this.

Restarts around cold boot were caused by a watchdog timing defect that is fixed
in Beta 1.0 — the first ping now happens as soon as the store answers, instead of
after a full interval. See `../CHANGELOG.md`. If you still see a timeout, the
journal lines immediately before it are the useful evidence.

## The database is growing

```bash
du -sh /var/lib/shield/shield.db
journalctl -u shield-agent | grep "Database maintenance" | tail -3
```

Maintenance runs periodically and does bounded work per pass, returning sooner
while a backlog remains. The `more_work` flag in those lines tells you whether it
is still draining. The size cap defaults to 2048 MB and trims oldest events
first; the file itself does not shrink, because SQLite reuses freed pages.

## An upgrade removed the AI runtime

Expected. Package installs rebuild the agent's virtualenv from scratch, by
design, so installs stay offline and reproducible. Your GGUF file survives
because it lives outside the virtualenv; `llama-cpp-python` does not.

Nothing in Beta 1.0 needs it. Reinstall only if you are experimenting with the
dormant worker:

```bash
sudo /opt/shield/.venv/bin/pip install llama-cpp-python
```

## Guided Q&A says a question is out of scope

Working as intended. Beta 1.0 answers five closed questions about the incident in
front of you. Anything else — general questions, other machines, requests to
take an action — is refused deterministically, without a model.

## Response actions do nothing

Check `nftables` is installed, that the privileged helper is active
(`systemctl status shield-privileged`), and that the policy permits the action.
Actions are verified after execution; a failed verification rolls back and
raises an alert rather than reporting success.

## Reporting a problem

Include the Shield version (`dpkg -s shield-monitor | grep Version`), your
distribution, the relevant journal excerpt **with addresses and hostnames
redacted**, and what you expected instead. For anything security-sensitive,
follow `../SECURITY.md` rather than opening a public issue.
