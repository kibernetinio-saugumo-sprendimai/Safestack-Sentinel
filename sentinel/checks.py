import os
import platform
import re
import stat
# Bounded inspection commands; no shell is used.
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .model import Finding

TRUSTED_COMMANDS = {
    "apt-get": ("/usr/bin/apt-get",),
    "lsof": ("/usr/sbin/lsof", "/usr/bin/lsof"),
    "scutil": ("/usr/sbin/scutil", "/usr/bin/scutil"),
    "ss": ("/usr/bin/ss", "/bin/ss"),
    "sshd": ("/usr/sbin/sshd",),
    "ufw": ("/usr/sbin/ufw", "/usr/bin/ufw"),
}
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def trusted_command(name: str) -> Optional[str]:
    for candidate in TRUSTED_COMMANDS.get(name, ()):
        path = Path(candidate)
        try:
            info = path.stat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            continue
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        return str(path)
    return None


@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def evidence(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


def query(cmd: List[str], timeout: float = 5.0) -> CommandResult:
    try:
        # Callers supply fixed absolute OS paths and literal inspection arguments.
        p = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=timeout, env=COMMAND_ENV,
            shell=False,
        )
        return CommandResult(p.stdout, p.stderr, p.returncode)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return CommandResult(stderr=f"unavailable: {exc}")


def run(cmd: List[str], timeout: float = 5.0) -> str:
    result = query(cmd, timeout)
    return result.evidence if result.ok else f"unavailable: {result.evidence}"


def platform_check() -> Finding:
    return Finding("platform", "info", "pass", f"Detected {platform.system()} {platform.release()}", platform.platform())


def firewall_check() -> Finding:
    system = platform.system()
    if system == "Darwin":
        result = query(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        match = re.search(r"\bstate\s*=\s*([01])\b", result.stdout, re.I)
        enabled = match.group(1) == "1" if result.ok and match else None
        guidance = "Review the macOS application firewall in System Settings > Network > Firewall."
    elif system == "Linux":
        command = trusted_command("ufw")
        if not command:
            return Finding("firewall", "high", "unknown", "No trusted UFW executable found", None,
                           "Review the host firewall manually (for example nftables or firewalld).")
        result = query([command, "status", "verbose"])
        match = re.search(r"^Status:\s*(active|inactive)\s*$", result.stdout, re.I | re.M)
        enabled = match.group(1).lower() == "active" if result.ok and match else None
        guidance = "Review UFW with an allowlist appropriate for this host."
    else:
        return Finding("firewall", "medium", "unknown", "Firewall check is not implemented for this OS")
    if enabled is None:
        return Finding("firewall", "high", "unknown", "Could not establish firewall state", result.evidence, guidance)
    return Finding("firewall", "high", "pass" if enabled else "fail",
                   "Firewall is enabled" if enabled else "Firewall is disabled", result.evidence, guidance)


def listening_ports() -> Finding:
    system = platform.system()
    if system == "Linux":
        name, args, scope = "ss", ["-lntup"], "TCP/UDP"
    elif system == "Darwin":
        name, args, scope = "lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], "TCP"
    else:
        return Finding("listening_ports", "medium", "unknown", "Listener check is not implemented for this OS")
    command = trusted_command(name)
    if not command:
        return Finding("listening_ports", "medium", "unknown", f"No trusted {name} executable found")
    result = query([command] + args)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    header_valid = bool(lines) and ("Local Address:Port" in lines[0] if system == "Linux" else lines[0].startswith("COMMAND"))
    if not result.ok or result.stderr.strip() or not header_valid:
        return Finding("listening_ports", "medium", "unknown", "Could not establish listening sockets", result.evidence)
    count = len(lines) - 1
    return Finding("listening_ports", "medium", "pass" if count == 0 else "review",
                   f"Detected {count} {scope} listening socket entries", lines[:50],
                   "Review every listener; visibility may be limited by the current user's permissions.")


def ssh_check() -> Finding:
    command = trusted_command("sshd")
    if not command:
        return Finding("ssh", "high", "unknown", "No trusted sshd executable found")
    result = query([command, "-T"])
    if not result.ok:
        return Finding("ssh", "high", "unknown", "Could not read effective SSH defaults", result.evidence)
    values = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].lower() in ("permitrootlogin", "passwordauthentication"):
            key = fields[0].lower()
            if key in values:
                return Finding("ssh", "high", "unknown", "Ambiguous SSH defaults", result.evidence)
            values[key] = fields[1].lower()
    if len(values) != 2:
        return Finding("ssh", "high", "unknown", "Incomplete effective SSH defaults", result.evidence)
    secure = all(value == "no" for value in values.values())
    # sshd -T resolves Include/defaults but does not evaluate connection-specific Match rules.
    return Finding("ssh", "high", "review" if secure else "fail",
                   "Global SSH defaults are hardened; review Match rules" if secure else "Global SSH defaults permit root or password authentication",
                   values, "Review sshd -T -C for relevant users and addresses, and validate configuration with sshd -t.")


def update_check() -> Finding:
    apt_get = trusted_command("apt-get")
    if platform.system() != "Linux" or not apt_get:
        return Finding("updates", "low", "unknown", "Automatic package update check is OS-specific")
    result = query([apt_get, "-s", "upgrade"], timeout=15)
    match = re.search(r"^(\d+) upgraded", result.stdout, re.M)
    if not result.ok or not match:
        return Finding("updates", "medium", "unknown", "Could not determine pending APT upgrades", result.evidence)
    count = int(match.group(1))
    return Finding("updates", "medium", "pass" if count == 0 else "review",
                   "No pending APT upgrades" if count == 0 else f"{count} APT upgrades are pending", count,
                   "Review and apply updates during a maintenance window; the local APT index may be stale.")


def privacy_check() -> Finding:
    evidence = {}
    if platform.system() == "Darwin":
        scutil = trusted_command("scutil")
        evidence["dns"] = (run([scutil, "--dns"]) if scutil else "trusted scutil executable not found")[:2000]
        evidence["location_note"] = "Review Location Services manually"
    elif platform.system() == "Linux":
        try:
            evidence["dns"] = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")[:2000]
        except OSError as exc:
            evidence["dns"] = str(exc)
        evidence["telemetry_note"] = "Review installed vendor telemetry services manually"
    return Finding("privacy", "medium", "review", "Privacy settings require local policy review", evidence,
                   "Confirm trusted DNS, disable unused telemetry, Bluetooth, and location services.")


def run_all() -> List[Finding]:
    return [platform_check(), firewall_check(), listening_ports(), ssh_check(), update_check(), privacy_check()]
