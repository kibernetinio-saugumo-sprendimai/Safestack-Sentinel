import json
from collections import deque
from pathlib import Path
from typing import List
from .safeio import append_no_follow

def append(report: dict, path: str) -> None:
    target = Path(path).expanduser()
    append_no_follow(str(target), (json.dumps(report, sort_keys=True) + "\n").encode(), 0o600)

def load(path: str, limit: int = 20) -> List[dict]:
    target = Path(path).expanduser()
    if limit <= 0 or not target.exists():
        return []
    lines = deque(maxlen=limit)
    with target.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            lines.append(line)
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
