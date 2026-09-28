# Privacy

Shield is a monitoring tool. It is worth being precise about what it records,
where that lives, and who can reach it.

## What stays on the machine

Monitoring and evidence storage are local by default. There is no telemetry
upload to the developers, crash reporting, licence check, or remote AI.

Data lives in `/var/lib/shield`: the SQLite database, packet captures, snapshots,
quarantined files, and backups.

## Optional Telegram notifications

If an administrator configures **both** `SHIELD_TELEGRAM_TOKEN` and
`SHIELD_TELEGRAM_CHAT_ID` for the agent, it sends alert severity, title and
detail to the Telegram Bot API over HTTPS. Critical alerts and forced
self-monitoring notifications can use this path. Without both settings,
this path makes no request. Remove either setting and restart the agent to
disable it.

Alert text passes through the shared secret-redaction rules before sending.
Redaction is pattern-based: addresses, hostnames and process paths may remain
in the text. The database, PCAPs and snapshots are not uploaded by this path.
Enable it only if you want Telegram to receive these notifications. Desktop
notifications are delivered locally and also use the shared redaction rules.

## What Shield records

On the host:

- process executions, with command paths and process identity
- file writes to monitored paths, and file-integrity changes
- outbound socket connections, with destination and owning process
- listening sockets
- USB device attachment, with vendor and product identifiers
- authentication events from the journal and auditd
- selected system and security configuration changes

On the local network:

- devices seen, with MAC addresses, addresses, and vendor lookups
- ARP and neighbour observations
- DNS resolver configuration and query observations
- connection and flow aggregates
- traffic statistics

This is detailed activity data about you and your network. Treat the database
as sensitive.

## Secret redaction

Redaction runs before storage and again before display. Private keys, tokens,
passwords, and similar patterns are replaced with a marker, including when they
appear nested inside other fields. It is pattern-based, so it is good rather
than perfect: do not assume a secret pasted into a monitored file is safe
because Shield redacts.

## Who can read it

- `root` on the monitored machine.
- Members of the `shield` group, through the agent socket and the interface.
- Anyone who can read `/var/lib/shield`, so keep its permissions intact.

## Retention

Events are retained for a configurable period (30 days by default) and the
database is capped by size (2048 MB by default). When the cap is reached, the
**oldest events** are trimmed first. Alerts and the forensic ledger are never
trimmed by that path, because conclusions and integrity records are small and
are what you need later.

## MAC address vendor lookups

Vendor names are resolved from a local IEEE database, or the bundled `manuf`
fallback. No lookup leaves the machine.

## If you share diagnostics

Logs, screenshots, database extracts, and packet captures routinely contain
addresses, hostnames, usernames, and process paths. Redact before attaching them
to an issue, or reproduce the problem with synthetic data. `../SECURITY.md`
covers reporting vulnerabilities privately.

## Monitoring other people

Shield observes the network segment it is attached to, which may include devices
belonging to other people. Running it on a network you do not control may be
unlawful and is, at minimum, a matter to settle with the people affected before
you start.
