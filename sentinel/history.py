import json
from pathlib import Path
from typing import List
from .safeio import append_no_follow

def append(report: dict, path: str) -> None:
    target = Path(path).expanduser()
    append_no_follow(str(target), (json.dumps(report, sort_keys=True) + "\n").encode(), 0o600)

def load(path: str, limit: int = 20) -> List[dict]:
    target = Path(path).expanduser()
    if not target.exists():
        return []
    rows = []
    for line in target.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
