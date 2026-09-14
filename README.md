# SafeStack Sentinel

Local security and privacy auditing for macOS, Kali Linux, and Raspberry Pi.
Sentinel is read-only by default. It produces a remediation plan but never
changes firewall, SSH, packages, or services unless a future command explicitly
implements an approved action.

## Quick start

```bash
python3 -m sentinel audit --json report.json --html report.html
python3 -m sentinel baseline create baseline.json /etc/ssh/sshd_config
python3 -m sentinel baseline verify baseline.json
python3 -m unittest discover -v
```

The project uses only the Python standard library.
