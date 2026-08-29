# Public Release Checklist

Work through this before making the repository public. Items marked **blocker**
must be resolved, not merely acknowledged.

## Code and tests

- [x] Full unprivileged test suite passes (2225 passed, 35 skipped, 0 failed)
- [x] Export tree verified independently of the development checkout
- [x] Package builds from the export
- [ ] Package built from the export installed into a clean machine or VM
- [x] No build caches, virtualenvs, or coverage output in the export

## Secrets and private data

- [x] No credentials, API keys, tokens, or private keys
- [x] No database files
- [x] No GGUF or other model files
- [x] No logs, PCAPs, or captured traffic
- [x] No developer username, hostname, or home paths
- [x] Real MAC addresses and LAN addresses from the development network replaced
      with documentation-range values
- [x] Documentation uses generic examples (`/home/user`, `192.0.2.x`,
      `example.com`)

## Licensing

- [x] Apache-2.0 `LICENSE` present, official text, copyright filled in
- [x] `NOTICE` lists third-party dependencies and their licences
- [x] PyQt6 (GPL-3.0) removed; interface migrated to PySide6 under LGPL-3.0
- [x] LGPL-3.0 obligations documented in `../NOTICE`
- [x] scapy (GPL-2.0) moved out of the core into `shield-packet-collector`,
      a separate program, package and process
- [x] Core proven to contain zero scapy imports (AST scan in the test suite)
- [x] Core `.deb` no longer depends on `python3-scapy`
- [ ] Helper component's own licence position reviewed by the maintainers
- [x] No vendored third-party source
- [x] No bundled fonts, icons, or datasets of unclear provenance

## Documentation

- [x] `README.md` claims verified against implementation
- [x] AI described accurately — dormant, unused, and not marketed
- [x] Known limitations stated, including the unresolved watchdog restarts
- [x] `SECURITY.md` with a private reporting route and no fabricated contact
- [x] `DISCLAIMER.md` covering authorised use
- [x] `CONTRIBUTING.md` with real commands and the architecture invariants
- [x] Testing and demo guides use benign actions only
- [ ] Installation instructions followed on a clean machine
- [ ] Quick start followed on a clean machine
- [ ] Internal links checked after the repository name is known

## Repository configuration

- [ ] **Enable private vulnerability reporting** (Settings → Code security →
      Private vulnerability reporting) — `SECURITY.md` points at it
- [ ] Repository description and topics set (see the release report)
- [ ] Default branch chosen and protected
- [ ] Visibility change made deliberately, not incidentally
- [ ] First release tagged and titled

## Screenshots

- [ ] Captured per `screenshots/README.md`
- [ ] Hostnames, addresses, MACs, usernames, and file paths scrubbed
- [ ] Reviewed by a second pair of eyes before upload

## Final

- [ ] `git status` clean in the export
- [ ] A person other than the author has read `README.md` end to end
- [ ] The licence question has an answer written down
