# Installation

Use `scripts/install-linux.sh` on Kali, Debian, Ubuntu or Raspberry Pi OS, and
`scripts/install-macos.sh` on macOS. Both create a project-local virtual
environment and install the CLI without changing firewall, SSH or package policy.

Run `./.venv/bin/safestack-sentinel audit --json report.json --html report.html`.

The project requires Python 3.9+ and cryptography 50.0.2+. Current cryptography
wheels support Apple Silicon macOS; Intel macOS may require a source build
with Rust and OpenSSL following https://cryptography.io/en/latest/installation/.
No Intel macOS or physical Pi validation is claimed by the CI matrix.
