# Screenshots

**This directory is intentionally empty of images.** No screenshots have been
captured for Beta 1.0. Nothing here is fabricated or mocked up.

This file specifies what to capture and what must be removed first.

## Capture these, in this order

| # | File | Screen | Should show |
|---|---|---|---|
| 1 | `overview.png` | Overview | live activity: devices seen, recent events, collector health |
| 2 | `incidents.png` | Incidents | the incident list with severity and scenario names |
| 3 | `incident-report.png` | Incidents → report | the ten deterministic sections, including confirmed facts and evidence references |
| 4 | `guided-qa.png` | Incidents → Ask about this incident | the five quick-action buttons and one answer with its evidence links |
| 5 | `expert-evidence.png` | Evidence | an event opened from a report reference |
| 6 | `network.png` | Devices / Traffic | discovered devices and traffic view |
| 7 | `response.png` | Response | an action with its level, preconditions, and rollback |
| 8 | `health.png` | Health | collector status and measured kernel probe coverage |

Five is enough for a README; eight covers the feature set.

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

## Before adding any image here

Confirm the checklist item in `../PUBLIC_RELEASE_CHECKLIST.md`, and have someone
other than the person who captured it look at each image.
