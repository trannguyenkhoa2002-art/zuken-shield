# Examples

Small, safe artefacts for running Shield in a lab you own.

Everything here is benign. Nothing installs software, exploits anything, or
changes system state beyond what the comments say. **Use only on machines you
own or are authorised to test.**

## `generate-benign-chain.sh`

Produces the telemetry pattern behind `BEHAVIOR_EXEC_WRITE_CONNECT`: a process
runs, writes a few files, then opens one outbound connection. Nothing malicious
happens — the *shape* is what Shield detects, which is exactly why a legitimate
installer can look similar and why the report states what is not established.

```bash
bash examples/generate-benign-chain.sh              # writes locally only
bash examples/generate-benign-chain.sh 192.0.2.10 18080   # add a connection
```

Requires `bpftrace` for the process and file-write events to be visible.

## `check-shield-health.sh`

Read-only. Prints service state, restart count, recent maintenance lines, kernel
probe coverage, and the database integrity result. Useful before concluding that
a detection is broken — usually a collector is simply not running.

```bash
bash examples/check-shield-health.sh
```

## What is deliberately absent

No exploit code, no credential attacks, no scanning tools, and no payloads.
Where the testing guide needs a scan, it uses `nmap` directly against a host you
own and says so explicitly. Shipping attack tooling inside a defensive project
would be a poor trade for a slightly more impressive examples directory.

See `../docs/TESTING_GUIDE.md` and `../docs/DEMO_SCENARIOS.md`.
