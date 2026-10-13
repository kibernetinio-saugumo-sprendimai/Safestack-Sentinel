import os
import platform
import re
import stat
import subprocess
from pathlib import Path
from typing import List, Optional

from .model import Finding


TRUSTED_COMMANDS = {
    "apt-get": ("/usr/bin/apt-get",),
    "lsof": ("/usr/sbin/lsof", "/usr/bin/lsof"),
    "scutil": ("/usr/sbin/scutil", "/usr/bin/scutil"),
    "ss": ("/usr/bin/ss", "/bin/ss"),
    "ufw": ("/usr/sbin/ufw", "/usr/bin/ufw"),
}


def trusted_command(name: str) -> Optional[str]:
    for candidate in TRUSTED_COMMANDS.get(name, ()):
        path = Path(candidate)
        try:
            info = path.stat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            continue
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        return str(path)
    return None


def run(cmd: List[str], timeout: float = 5.0) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        return (p.stdout + p.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return f"unavailable: {exc}"


def platform_check() -> Finding:
    return Finding("platform", "info", "pass", f"Detected {platform.system()} {platform.release()}", platform.platform())


def firewall_check() -> Finding:
    system = platform.system()
    if system == "Darwin":
        out = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        ok = "enabled" in out.lower() or "state = 1" in out.lower()
        return Finding("firewall", "high", "pass" if ok else "fail",
                       "macOS application firewall is enabled" if ok else "macOS application firewall is not confirmed enabled",
                       out, "Enable the macOS application firewall in System Settings > Network > Firewall.")
    if system == "Linux":
        ufw = trusted_command("ufw")
        if ufw:
            out = run([ufw, "status", "verbose"])
            ok = "status: active" in out.lower()
            return Finding("firewall", "high", "pass" if ok else "fail",
                           "UFW is active" if ok else "UFW is not active", out,
                           "Review and enable UFW with an allowlist appropriate for this host.")
        return Finding("firewall", "high", "unknown", "No UFW executable found", None,
                       "Check the host firewall manually (for example nftables or firewalld).")
    return Finding("firewall", "medium", "unknown", "Firewall check is not implemented for this OS")


def listening_ports() -> Finding:
    if platform.system() == "Linux":
        ss = trusted_command("ss")
        out = run([ss, "-lntup"]) if ss else "trusted ss executable not found"
    elif platform.system() == "Darwin":
        lsof = trusted_command("lsof")
        out = run([lsof, "-nP", "-iTCP", "-sTCP:LISTEN"]) if lsof else "trusted lsof executable not found"
    else:
        out = "unsupported platform"
    lines = [line for line in out.splitlines() if line.strip()]
    # Header-only output means no listeners were found.
    count = max(0, len(lines) - 1)
    return Finding("listening_ports", "medium", "pass" if count == 0 else "review",
                   f"Detected {count} listening socket entries", lines[:50],
                   "Review every listener and disable services that are not required.")


def ssh_check() -> Finding:
    config_paths = ["/etc/ssh/sshd_config.d/99-hardening.conf", "/etc/ssh/sshd_config"]
    found: Optional[str] = None
    for path in config_paths:
        if os.path.isfile(path):
            found = path
            break
    if not found:
        return Finding("ssh", "high", "unknown", "SSH configuration was not found")
    text = open(found, encoding="utf-8", errors="replace").read()
    secure = all(re.search(rf"^\s*{key}\s+{value}\s*$", text, re.I | re.M)
                 for key, value in (("PermitRootLogin", "no"), ("PasswordAuthentication", "no")))
    return Finding("ssh", "high", "pass" if secure else "fail",
                   "SSH root and password login are disabled" if secure else "SSH hardening directives are incomplete",
                   found, "Set PermitRootLogin no and PasswordAuthentication no, then validate sshd -t.")


def update_check() -> Finding:
    apt_get = trusted_command("apt-get")
    if platform.system() != "Linux" or not apt_get:
        return Finding("updates", "low", "unknown", "Automatic package update check is OS-specific")
    out = run([apt_get, "-s", "upgrade"], timeout=15)
    match = re.search(r"^(\d+) upgraded", out, re.M)
    count = int(match.group(1)) if match else None
    if count is None:
        return Finding("updates", "medium", "unknown", "Could not determine pending APT upgrades", out)
    return Finding("updates", "medium", "pass" if count == 0 else "review",
                   "No pending APT upgrades" if count == 0 else f"{count} APT upgrades are pending", count,
                   "Review and apply updates during a maintenance window.")


def privacy_check() -> Finding:
    evidence = {}
    if platform.system() == "Darwin":
        scutil = trusted_command("scutil")
        evidence["dns"] = (run([scutil, "--dns"], timeout=5) if scutil else "trusted scutil executable not found")[:2000]
        evidence["location_note"] = "Review Location Services manually"
    elif platform.system() == "Linux":
        try:
            evidence["dns"] = open("/etc/resolv.conf", encoding="utf-8", errors="replace").read()[:2000]
        except OSError as exc:
            evidence["dns"] = str(exc)
        evidence["telemetry_note"] = "Review installed vendor telemetry services manually"
    return Finding("privacy", "medium", "review", "Privacy settings require local policy review", evidence,
                   "Confirm trusted DNS, disable unused telemetry, Bluetooth, and location services.")


def run_all() -> List[Finding]:
    return [platform_check(), firewall_check(), listening_ports(), ssh_check(), update_check(), privacy_check()]
