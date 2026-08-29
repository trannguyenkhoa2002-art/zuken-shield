# Screenshots

**This directory holds no images, and Beta 1.0 does not need any.** The public
`README.md` deliberately carries no screenshots: the release stands on the
product description, the architecture, and the documentation. Nothing here is a
blocker.

This file stays as the specification for whoever captures a set later — what to
capture, and what must be scrubbed first. A set was captured during the Beta 1.0
review and then removed from the repository along with the README section that
referenced it; the notes below are what that exercise established.

**If you capture screenshots, do not photograph a production host.** Seed a
synthetic lab database through Shield's own pipeline instead, so the incidents,
report sections, answers and state transitions on screen are genuinely computed
by Shield rather than typed into a picture, while the network behind them is
fictional: RFC 5737 `192.0.2.0/24` addresses, IANA documentation MACs
(`00:00:5E:00:53:xx`), and lab device names.

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

Eight covers the feature set; five would be enough for any page that wants
them. Nothing in the project links to these filenames today.

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
- If some page is later to show them, reference them as
  `docs/screenshots/<file>.png` — nothing does today

## Before adding or replacing any image here

Confirm the checklist item in `../PUBLIC_RELEASE_CHECKLIST.md`, and have someone
other than the person who captured it look at each image. Keep the filenames
above so this specification stays accurate.
