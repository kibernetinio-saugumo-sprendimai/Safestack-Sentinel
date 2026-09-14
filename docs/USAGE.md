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

Use a profile to document the intended host role:

```bash
python -m sentinel plan --profile raspberry-pi-vpn --json plan.json
```

The plan is informational and marked `read_only`; it never executes its
commands.

## Sign reports

Keep the private key offline where possible:

```bash
python -m sentinel keygen sentinel-private.pem sentinel-public.pem
python -m sentinel sign report.json report.sig sentinel-private.pem
python -m sentinel verify-signature report.json report.sig sentinel-public.pem
```

The signature file is detached and base64 encoded. Do not commit the private
key or reports containing sensitive host information.

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
