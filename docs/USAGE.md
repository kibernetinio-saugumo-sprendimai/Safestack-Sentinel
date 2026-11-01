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

Key generation requires two different, unused output paths. Existing files
and symlinks are never overwritten; choose new filenames for key rotation.
If writing the public key fails after the private key was saved, retain that
private key and inspect the error before retrying with new output paths.

## File-integrity baselines

```bash
python -m sentinel baseline create baseline.json path/to/file /etc/ssh/sshd_config
python -m sentinel baseline verify baseline.json
```

Baseline paths are stored exactly as supplied. Keep the baseline in a trusted,
read-only location if it is used for incident response. A baseline proves only
that the bytes match the recorded digest; it does not prove that the original
file was trustworthy.

Relative paths are resolved from the current working directory; verify from
the same directory used during creation. Baselines must contain at least one
entry, unique paths and lowercase SHA-256 digests. Missing or unreadable files
are reported as `FAIL`, and verification continues for the remaining files.
Malformed baselines and unsafe targets cause verification to fail with a
diagnostic and exit code `2`.
The baseline output must differ from every tracked file, including symbolic
and hard-link aliases. A rejected creation leaves the tracked files intact.

## Exit codes

- `0`: command completed successfully;
- `2`: baseline verification failed, or signature verification failed;
- other non-zero codes: invalid arguments or an operational error.

## Built-in profile labels

Available profiles are default, kali-vm, ubuntu-server, raspberry-pi-vpn and
macos. A plan records the selected profile as metadata; it does not change
checks or configure a VPN. Profiles are bundled in Python, not external files.
Inspect status_counts as well as score. Secure SSH global defaults still need
Match-rule review. Keep private keys outside the dashboard report directory.

Profiles select the checks used by `plan --profile NAME`. Both `macos` and
`macos-desktop` omit SSH and APT checks. All built-in profiles ship in the Python
package, without depending on external configuration files.
