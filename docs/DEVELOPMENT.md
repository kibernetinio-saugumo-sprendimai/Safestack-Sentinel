# Development

The project targets Python 3.9 or newer and requires cryptography for Ed25519 signing.

Run the checks before committing:

```bash
python -m pip install -e .
python -m unittest discover -v
python -m compileall -q sentinel tests
python -m sentinel audit --json /tmp/sentinel.json
```

New checks should be deterministic, bounded by a timeout, explicit when a
platform is unsupported, and covered by tests. Never silently convert a failed
network or system query into a fabricated value.

Keep report output escaped and keep baseline verification byte-based. Changes
that add network access, privileged writes, automatic remediation, or telemetry
need a separate security review.

CI covers Python 3.9 and 3.12 on Linux and macOS. Bandit exceptions are limited
to the reviewed subprocess import and fixed-argument, shell-free invocation.
Dependency auditing runs even if Bandit fails.
