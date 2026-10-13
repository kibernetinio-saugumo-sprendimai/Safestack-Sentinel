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

## Observation coverage

Inspection failures and missing commands are unknown, never fabricated passes.
SSH uses sshd -T to read effective global defaults. Hardened global defaults
remain review because connection-specific Match rules require sshd -T -C checks
for relevant users and addresses. This does not test a running SSH daemon.
On macOS listener inspection covers TCP only and is limited by user visibility.
APT checks use the existing local index and do not refresh it.
Failed or invalid opt-in plugins produce unknown findings. Reports include
assessment and status_counts; a score of 100 with unknown/review findings is not a clean bill
of health. Telegram is an explicit network-enabled exception to local operation,
uses a fixed HTTPS host and does not follow redirects.
