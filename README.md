# SafeStack Sentinel

SafeStack Sentinel is a local, read-only security and privacy auditor for
macOS, Kali Linux, Ubuntu, and Raspberry Pi systems. It checks the host,
reports evidence, and produces remediation guidance without changing firewall,
SSH, packages, services, or user files.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m sentinel audit --json report.json --html report.html
python -m unittest discover -v
```

Create and verify a file-integrity baseline:

```bash
python -m sentinel baseline create baseline.json /etc/ssh/sshd_config
python -m sentinel baseline verify baseline.json
```

The MVP uses only the Python standard library. See [`docs/USAGE.md`](docs/USAGE.md)
for all commands and [`docs/SECURITY.md`](docs/SECURITY.md) for the trust model.

## What it checks

- host platform and kernel identity;
- firewall state on macOS and Linux/UFW;
- listening network sockets;
- SSH root and password authentication directives;
- pending APT upgrades on Debian-family systems;
- SHA-256 baselines for selected files.

The report includes a score, severity, status, evidence, and a suggested
remediation. A `review` or `unknown` result is deliberately not treated as a
pass.

## Design principles

Sentinel is local-first, read-only by default, explicit about uncertainty, and
free of telemetry. It does not scan third-party targets or make network
changes. Any future remediation command must be separate from the audit path,
show a dry-run plan, and require explicit confirmation.

## Repository layout

```text
sentinel/       auditor, reports, and integrity commands
tests/          unit tests
docs/           operational and security documentation
```

## License

Released under the MIT License. See [`LICENSE`](LICENSE). SafeStack names and
marks remain the property of their respective owners.
