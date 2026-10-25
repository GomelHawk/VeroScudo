# Contributing to VeroScudo

Thanks for helping. A few ground rules keep this project safe to change - it manipulates
firewalls, so a careless merge can lock someone out of their own laptop.

## Before you change the guard logic

1. Read `docs/ARCHITECTURE.md` - the state machine is shared by every platform, and a change
   on one must keep the same meaning on the others.
2. Never test a reconnect path by breaking a live link before proving the redial works under
   the kill-switch. The offline tests (`windows/tests-local/`, `linux/tests-local/`) do it in
   the safe order and restore the machine in a `finally` block.
3. Keep "strict" strict: with the VPN on, a lost connection must never lead to raw internet
   unless the user turns the VPN off. No timers, no fallbacks, no rescue buttons.
4. Answer the hardening checklist in `docs/SECURITY.md` (fail closed? who can influence the input?
   every permit scoped?) in the PR description.

## Development

- Windows: PowerShell 5.1 compatible (ships with Windows). Unit tests use Pester 5 with
  mocked cmdlets (`windows/tests/`). `Invoke-ScriptAnalyzer -Path windows -Recurse` must be clean.
- Linux and macOS share the Python package in `linux/` (backends: `firewall.py`+`nm.py` / `pf.py`+`scutil.py`).
  Python 3.10+. `cd linux && pip install -e '.[dev]' && pytest && ruff check .`
- CI runs both on every pull request. The real end-to-end tests cannot run in CI; run the
  local ones on your machine and paste the log into the PR.

## Releasing

A release is what users install over the version they already have, so test exactly that:

1. Bump the version in `windows/VeroScudo.Core.psm1` and `linux/veroscudo/__init__.py` (the Linux
   package reads it from there); move
   `[Unreleased]` in `CHANGELOG.md` to the new version and date.
2. Unit tests and lint pass (see Development).
3. **Windows upgrade test** - `windows/tests-local/Test-Upgrade.ps1` (elevated) must end with
   `PASS`. It installs the previous release and this checkout over it, twice, and checks one tray,
   up-to-date files and icons, and no leftovers. A first install onto a clean machine is not enough.
4. If the guard logic changed: `Test-Offline.ps1`, then `Test-Live.ps1`.
5. Anything that touches assets or packaging: check the files `release.yml` copies, and look at the
   result (tray, windows, About) after the upgrade - not just the code.
6. Commit, tag `vX.Y.Z`, push the tag; the Release workflow builds the archives.

Rules any change to the installers or the tray must keep: a rerun or upgrade is idempotent and
leaves no files from the old version behind; a running tray/daemon is restarted so the new code
runs; only one tray per session; a missing asset is logged, never silently substituted.

## Pull requests

- One topic per PR, with the test log for anything that touches the guard logic.
- Update `README.md`/`docs/` in the same PR when behaviour changes.
