# Contributing to Zuken Shield

Thank you for considering it. This project has a few opinions that are stronger
than usual, and they exist because breaking them has caused real bugs. Please
read the invariants before writing code.

## Development setup

```bash
git clone https://github.com/trannguyenkhoa2002-art/zuken-shield.git
cd zuken-shield
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e '.[dev]'
```

`--system-site-packages` is deliberate: PySide6, scapy, and pyqtgraph are expected
to come from the distribution rather than PyPI.

## Running the tests

```bash
.venv/bin/python -m pytest -q            # everything that runs unprivileged
.venv/bin/python -m pytest tests/test_detectors.py -q
sudo .venv/bin/python -m pytest -q -m netns   # tests needing root/namespaces
```

The unprivileged suite must be green before you open a pull request. Around 35
tests are skipped without root; that is expected.

## Building the package

```bash
bash packaging/build-deb.sh
sudo apt install -y ./dist/shield-monitor_*_amd64.deb
```

## Architecture invariants

These are not style preferences. A change that breaks one of them will be asked
to change, however good the rest of it is.

**1. Evidence first.** No conclusion without a stored, resolvable evidence
reference. An edge in the evidence graph with no valid reference is a bug, not a
shortcut — it produces a claim nobody can check later.

**2. Deterministic code is the authority.** Measurement decides what is true.
Interpretation may explain it and may be dropped entirely without changing what
Shield reports.

**3. AI may never override a canonical fact.** Model output is prose. It cannot
set severity, scenario, evidence references, counts, identifiers, timestamps, or
recommendations. Every generated sentence goes through `clean_prose` in
`shield/report/template.py` — that function is the single gate, and a second
copy of its logic is a security bug waiting to drift.

**4. No duplicate canonical primitives.** One scenario registry, one evidence
resolver, one prose guard, one failure-code mapping. When you need something
that already exists in a slightly different shape, extend the original.

**5. Response actions go through the policy path.** Every action must have an
entry in `ACTION_SPECS` with a level, blast radius, reversibility, and
verification. Nothing executes by calling a shell directly.

**6. The interface decides nothing.** It renders what the agent sends. Scenario
eligibility, epistemic state, and evidence validity are backend decisions.

**7. Fail closed.** If isolation, validation, or a required resource is
unavailable, do less — never more.

## New detectors

A new detector needs:

- A stable `rule_id`, and an entry in the scenario registry
  (`shield/report/scenarios.py`) so reports know how to describe it.
- Tests covering both firing and not firing, with realistic evidence.
- Evidence that resolves: the alert must carry references a reader can follow.
- An honest severity. If it is noisy, say so in the pull request.

## Public claims

Any change to `README.md` or the documentation that adds a capability claim must
point at the code that implements it. "Planned" belongs in `ROADMAP.md`. This
rule exists because a security tool that overstates itself is worse than one
that says less.

## Style

- Follow the surrounding code. Run `ruff` and `mypy` before submitting.
- Comments explain *why*, especially when the obvious approach was wrong. Much
  of this codebase is commented that way on purpose.
- Vietnamese comments are welcome and normal here; public documentation and
  identifiers are English.

## Testing in a lab

`docs/TESTING_GUIDE.md` covers safe validation on hardware you own. Please do
not attach real capture data to issues — reproduce with synthetic data instead.
