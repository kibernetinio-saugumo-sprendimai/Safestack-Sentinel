# Architecture

The project has four small layers:

1. `sentinel.checks` runs bounded, read-only operating-system checks.
2. `sentinel.model` defines findings and calculates a transparent score.
3. `sentinel.report` serializes JSON and escaped HTML reports.
4. `sentinel.integrity` creates and verifies SHA-256 file baselines.

`sentinel.cli` is the only command-line entry point. It composes checks and
does not contain privileged mutation logic. This separation is intentional:
future remediation code must not be reachable accidentally from `audit`.

The score is a prioritization aid, not a security certification. Critical,
high, medium, and low failed findings deduct 35, 20, 10, and 3 points
respectively, with a floor of zero.
