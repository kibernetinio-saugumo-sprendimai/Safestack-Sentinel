import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load(name: str) -> dict:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        raise ValueError(f"Invalid profile name: {name}")
    path = ROOT / "profiles" / f"{name}.json"
    if not path.is_file():
        raise ValueError(f"Unknown profile: {name}")
    profile = json.loads(path.read_text(encoding="utf-8"))
    from .checks import CHECKS
    names = profile.get("checks")
    if not isinstance(names, list) or not all(isinstance(n, str) and n in CHECKS for n in names):
        raise ValueError(f"Invalid checks in profile: {name}")
    return profile
