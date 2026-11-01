"""Built-in host labels, available in source checkouts and installed packages."""
from copy import deepcopy

PROFILES = {
    "default": {"name": "default", "role": "general-purpose host"},
    "kali-vm": {"name": "kali-vm", "role": "Kali Linux virtual machine"},
    "ubuntu-server": {"name": "ubuntu-server", "role": "Ubuntu server"},
    "raspberry-pi-vpn": {"name": "raspberry-pi-vpn", "role": "Raspberry Pi VPN host"},
    "macos-desktop": {"name": "macos-desktop", "role": "macOS workstation"},
    "macos": {"name": "macos", "role": "macOS workstation"},
}


def load(name: str) -> dict:
    if name not in PROFILES:
        raise ValueError(f"Unknown profile: {name}")
    from .checks import CHECKS
    profile = deepcopy(PROFILES[name])
    profile["checks"] = [check for check in CHECKS
                         if name not in ("macos", "macos-desktop") or check not in ("ssh", "updates")]
    return profile
