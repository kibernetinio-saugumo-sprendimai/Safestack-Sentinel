import hashlib
import json
from pathlib import Path


def digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create(paths, output: str) -> None:
    data = {str(Path(p)): digest(p) for p in paths}
    Path(output).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def verify(baseline: str):
    data = json.loads(Path(baseline).read_text(encoding="utf-8"))
    return [(path, digest(path) == expected) for path, expected in data.items()]
