import json
from pathlib import Path
from typing import List

def append(report: dict, path: str) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(report, sort_keys=True) + "\n")

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
