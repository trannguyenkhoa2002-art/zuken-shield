# Disclaimer

Zuken Shield is a defensive security monitoring tool. It is provided under the
Apache License 2.0, **without warranty of any kind**, express or implied. See
the `LICENSE` file for the governing terms.

## Authorised use only

Run Shield only on systems and networks that you own, or that you have explicit
written authorisation to monitor.

Shield observes network traffic on the interface it is given, discovers devices
on the local network, and records process, file, and connection activity on the
host. In many jurisdictions, doing this to a network or machine you do not
control is unlawful — regardless of intent, and regardless of whether the tool
is defensive.

If you are testing in a lab, make sure the lab is yours.

## No guarantee of detection

Shield can miss things. Detection depends on which collectors are running, on
whether kernel telemetry is available, on how the host is configured, and on the
detection rules themselves. An absence of alerts is not evidence that nothing
happened.

Shield is not antivirus, does not remove threats, and is not a substitute for
patching, backups, least privilege, or a competent security programme.

## Beta software

Beta 1.0 has not had an independent security review, and it has not completed
long-duration soak testing. It runs as root because kernel telemetry requires
it. Evaluate it accordingly.

## Response actions

Shield can take limited, reversible actions on the host it monitors, such as
blocking an address or isolating the endpoint. These are off unless configured.
An automated response can disrupt legitimate work. Understand the policy before
enabling anything beyond alerting.

## Your data

Everything Shield collects stays on the machine. Nothing is uploaded. That also
means the evidence database is yours to protect: it contains detailed activity
about the host and the local network, and it should be treated as sensitive.
