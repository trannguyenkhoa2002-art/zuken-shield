# Installation

## Requirements

- **Ubuntu 26.04 LTS or newer** for the packaged install. This is not a
  preference: the interface needs PySide6, and `python3-pyside6.*` first appears
  in Ubuntu 26.04. Ubuntu 24.04 ships only PySide2 (Qt 5), so the `.deb`
  dependencies cannot be satisfied there. On 24.04 you can still run from a
  source checkout with `pip install PySide6`, but that gives up the offline,
  distribution-only install the package is built around.
- Python 3.10 or newer
- systemd
- `sudo`/root access — the agent needs it for kernel telemetry and other
  privileged host observations; optional packet capture runs in the separate
  `shield-packet-collector` service
- x86-64 (the package is built for `amd64`)

Optional but recommended:

- `bpftrace` — process, file-write, and socket-connect telemetry. Without it
  Shield runs with reduced endpoint visibility and says so.
- `nftables` — required for network response actions.
- `auditd` — richer authentication and system-call telemetry.

## Recommended: build and install the package

```bash
git clone https://github.com/trannguyenkhoa2002-art/zuken-shield.git
cd zuken-shield
bash packaging/build-deb.sh
sudo apt install -y ./dist/shield-monitor_*_amd64.deb
```

This installs the agent and the privileged helper as systemd services, enables
them, and creates a `shield` group so the desktop interface can reach the agent
socket.

The install is **offline**: it builds a virtualenv using packages your
distribution already provides and never contacts PyPI.

### After installing

Log out and back in once, so your account picks up the new `shield` group.

```bash
systemctl status shield-agent
shield                      # opens the interface
```

## Alternative: run from a source checkout

For development only — no systemd services, and you must supply privileges
yourself.

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e '.[dev]'
sudo .venv/bin/python -m shield.agent --help
```

## Optional: local AI runtime

**Not required.** No feature in Beta 1.0 uses a model, and guided Q&A is fully
deterministic. Install this only if you intend to experiment with the dormant
worker infrastructure.

```bash
sudo /opt/shield/.venv/bin/pip install llama-cpp-python
```

The path matters: the model worker runs isolated (`python -I`) and deliberately
ignores your user and system site-packages, so a runtime installed elsewhere is
invisible to it.

A GGUF model file is **not** included in this repository and is never downloaded
by Shield. If you supply one, place it under `/opt/shield/models`, owned by
root and world-readable.

**Reinstall the runtime after every Shield upgrade.** Package installs rebuild
the virtualenv from scratch by design.

## Uninstalling

```bash
sudo apt remove shield-monitor      # keeps data in /var/lib/shield
sudo apt purge shield-monitor       # removes data as well
```

## Where things live

| Path | Contents |
|---|---|
| `/opt/shield` | application code and its virtualenv |
| `/var/lib/shield` | database, PCAPs, snapshots, backups |
| `/run/shield` | agent IPC socket |
| `/usr/lib/systemd/system` | service units |

## Troubleshooting

See `TROUBLESHOOTING.md`.
