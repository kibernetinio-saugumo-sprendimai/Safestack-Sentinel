# Operations

Run Sentinel from a virtual environment and keep reports outside public web
directories:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m sentinel audit --json "$HOME/safestack-reports/$(date +%F).json"
```

For scheduled audits, use the operating system scheduler to invoke the read-
only command. Review `unknown` and `review` findings before changing the host.
Do not run the tool as root unless a specific read-only check needs privileged
visibility; root does not improve the correctness of every check.

Retain reports according to your incident-response policy. Reports can contain
hostnames, paths, service names, and listening ports.

For Linux, copy `docs/safestack-sentinel.service` and `.timer` to
`/etc/systemd/system/`, then run `systemctl daemon-reload` and
`systemctl enable --now safestack-sentinel.timer`. For macOS, replace
`USERNAME` in `docs/com.safestack.sentinel.plist` and load it with `launchctl`.
