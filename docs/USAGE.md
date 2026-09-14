# Usage

All commands are read-only except for writing the requested report or baseline
file.

## Audit a host

```bash
python -m sentinel audit
python -m sentinel audit --json report.json
python -m sentinel audit --json report.json --html report.html
```

When `--json` is omitted, the JSON report is printed to standard output. HTML
is optional and is intended for local review or archival.

The command exits zero when the audit completes. A completed audit can still
contain `fail`, `review`, or `unknown` findings; inspect the report before
making changes.

## File-integrity baselines

```bash
python -m sentinel baseline create baseline.json path/to/file /etc/ssh/sshd_config
python -m sentinel baseline verify baseline.json
```

Baseline paths are stored exactly as supplied. Keep the baseline in a trusted,
read-only location if it is used for incident response. A baseline proves only
that the bytes match the recorded digest; it does not prove that the original
file was trustworthy.

## Exit codes

- `0`: command completed successfully;
- `2`: baseline verification found a mismatch;
- other non-zero codes: invalid arguments or an operational error.
