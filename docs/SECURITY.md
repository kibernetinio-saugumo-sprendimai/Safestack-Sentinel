# Security model

Sentinel is an observation tool. The audit command does not call package
managers, enable services, change firewall rules, edit SSH configuration, or
delete files. Commands are executed only for read-only inspection and are
bounded by timeouts.

## Trust boundaries

- The host operating system and its command output are untrusted evidence.
- A report is an observation, not a guarantee that a host is secure.
- A `pass` result means only that the implemented check observed the expected
  condition.
- `unknown` means the check could not establish a fact and must be reviewed.
- HTML report fields are escaped before rendering.

## Privacy

Sentinel does not send telemetry or contact a remote service. Listening socket
output and file paths may be sensitive, so store reports with restrictive
permissions and do not publish them without review.

## Scope limits

Sentinel is not an intrusion detector, vulnerability scanner, antivirus, or
penetration-testing tool. It does not validate application-level security,
cloud permissions, firmware, physical access, or the correctness of every
firewall rule.

## Reporting vulnerabilities

Do not publish an unpatched vulnerability with host reports or credentials.
Open a private report with reproduction steps, affected commit, impact, and a
minimal remediation proposal.
