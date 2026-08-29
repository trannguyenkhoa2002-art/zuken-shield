# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| Beta 1.0 (package 3.0.0a2) | Yes |
| Everything earlier | No |

Beta 1.0 is the first release published from this repository. Earlier internal
versions were never published and receive no fixes.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through **GitHub Security Advisories**: go to the repository's
**Security** tab and choose **Report a vulnerability**. This creates a private
advisory visible only to you and the maintainers.

> **Status:** private vulnerability reporting is **not enabled yet**, and while
> this repository is private it cannot be — the setting is not offered here, and
> GitHub's API reports the feature as absent rather than merely switched off.
> The route described above therefore starts working only once the repository is
> public. **Enable it in the same sitting as the visibility change** (Settings →
> Code security → Private vulnerability reporting), so there is no window in
> which the repository is readable but this file describes a reporting path that
> does not exist. Until it is on, do not use public Issues for a security
> report — wait, or contact a maintainer through the repository's own channels.
> This file deliberately contains no email address, because a security contact
> that does not exist is worse than none.

### What to include

- What the problem is, and what an attacker gains.
- The affected component: agent, privileged helper, interface, packaging, or a
  specific module.
- Version (`dpkg -s shield-monitor`) and distribution.
- Minimal reproduction steps.
- Any logs — **with addresses, hostnames, and user data redacted**.

### What to expect

This is a small project with no paid staff, so no response-time guarantee is
offered. Realistically:

- Acknowledgement when a maintainer next picks up reports.
- An assessment of whether the report is reproducible and in scope.
- A fix or a documented decision not to fix, with reasoning.
- Credit in the release notes if you want it.

## Scope

In scope:

- Privilege escalation from the interface or the IPC socket to the root agent.
- Escape from the privileged helper's fixed operation set to arbitrary commands.
- Escape from the isolated AI worker (process, cgroup, or network confinement),
  even though no shipped feature currently starts it.
- Injection into detection, correlation, or reporting that causes Shield to
  fabricate or suppress evidence.
- Leaking secrets past the redaction layer into the database, the interface, or
  exported reports.
- Response actions that execute outside the policy path, or that cannot be
  rolled back as documented.

Out of scope:

- Anything requiring root on the monitored host — Shield's agent already runs as
  root by design.
- Missed detections, false positives, and detection-quality disagreements. Those
  are ordinary issues; open them publicly.
- Vulnerabilities in dependencies. Report those upstream; tell us if Shield's
  use makes them meaningfully worse.
- Findings from running Shield on a system you are not authorised to test.

## Handling

Shield collects sensitive local data by design. When you report, assume any
attached artefact may contain hostnames, addresses, usernames, and process
paths, and redact accordingly. Reports will not be shared beyond the maintainers
without your agreement.
