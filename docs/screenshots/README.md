# Screenshots

These are renders of the **real** Shield interface — the shipped PySide6 widgets,
the shipped report builder, the shipped guided-Q&A router, and the shipped
evidence query layer. Nothing here is a mockup, a drawing, or an edited image.

**The data behind them is a synthetic lab dataset, not a production host.** The
database was seeded through Shield's own pipeline — events, alerts, the
correlation engine, the incident store, and the response job state machine — so
every incident, report section, answer, and state transition on screen was
computed by Shield rather than typed into a picture. What is not real is the
network: addresses come from the RFC 5737 documentation range `192.0.2.0/24`,
MAC addresses from the IANA documentation range `00:00:5E:00:53:xx`, and the
device names are lab fixtures. No collectors were running against a real host,
and no packet capture, nftables rule, or privileged action was executed.

## The set

| # | File | Screen | Shows |
|---|---|---|---|
| 1 | `overview.png` | Overview | posture tiles, devices online, live activity |
| 2 | `incidents.png` | Incidents | correlated incidents with risk, MITRE, and why the alerts were grouped |
| 3 | `incident-report.png` | Incidents → report | the deterministic sections, confirmed facts, and evidence references |
| 4 | `guided-qa.png` | Incidents → Ask about this incident | the five quick-action buttons and three answered questions with evidence links |
| 5 | `expert-evidence.png` | Expert Evidence | the bounded query surface with an event opened |
| 6 | `network.png` | Devices | discovered devices, the observed profile, and "why Shield thinks this" |
| 7 | `response.png` | Response | a proposed and a verified action, with state history and post-verification evidence |
| 8 | `health.png` | Security Center | collector health, MITRE coverage, and Shield's own health |

Five of these are used in `../../README.md`; all eight are listed here.

## Scrub before uploading

Shield's interface is full of real data by design. Every screenshot must be
checked for:

- **hostnames** — including the window title and any host column
- **IP addresses** — replace or blur anything outside documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- **MAC addresses** — real ones identify real hardware; a randomised MAC is
  still a real device on someone's network
- **usernames and home directory paths** — `/home/<name>/…` in process paths
- **process command lines** — these leak file names and arguments
- **device vendor names** — enough of them together identify a household
- **SSIDs and network names**
- **timestamps** — usually fine, but they reveal activity patterns

Prefer capturing from a **purpose-built lab** with synthetic devices rather than
editing a screenshot of your own network. Blurring is easy to under-apply, and a
redacted screenshot still leaks layout and counts.

## Conventions

- PNG, captured at a normal window size — do not scale up
- Light or dark theme consistently across the set
- English interface for the primary set; a Vietnamese one is welcome as an extra
- Reference from `README.md` as `docs/screenshots/<file>.png` once present

## Before adding or replacing any image here

Confirm the checklist item in `../PUBLIC_RELEASE_CHECKLIST.md`, and have someone
other than the person who captured it look at each image. If you re-capture,
keep the filenames — `../../README.md` links to them directly.
