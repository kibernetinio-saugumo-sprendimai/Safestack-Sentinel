import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    path = ROOT / "profiles" / f"{name}.json"
    if not path.is_file():
        raise ValueError(f"Unknown profile: {name}")
    return json.loads(path.read_text(encoding="utf-8"))
