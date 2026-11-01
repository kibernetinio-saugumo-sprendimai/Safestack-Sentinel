# Changelog

## 0.1.0 - 2026-09-14

- Initial read-only audit CLI.
- macOS and Linux firewall checks.
- Listening socket, SSH, and APT update checks.
- JSON and escaped HTML reports.
- SHA-256 file-integrity baselines.
- Unit tests and MIT licensing.

## Unreleased

- Install declared dependencies in CI and test Linux/macOS with Python 3.9/3.12.
- Preserve command exit status and mark failed observations unknown.
- Inspect effective SSH global defaults without claiming Match-rule coverage.
- Bundle informational host profiles and retain their label in plans.
- Surface failed plugins and observation status counts.
- Run dependency audit independently of Bandit and document scoped exceptions.
- Use fixed-host HTTPS Telegram notifications and ignore local key artifacts.
- Refresh source checksums; use the installed interpreter for macOS scheduling.
- Require cryptography 50.0.2 or newer within major version 50; remove the
  upper bound that kept the dependency audit on a known-vulnerable release.
