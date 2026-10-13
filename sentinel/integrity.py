import hashlib
import json
import stat
from pathlib import Path
from .safeio import atomic_write

MAX_BASELINE_BYTES = 1024 * 1024
MAX_BASELINE_ENTRIES = 10000
MAX_DIGEST_BYTES = 1024 * 1024 * 1024


def _regular_file(path: Path, max_bytes: int) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to hash symlink: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"refusing to hash non-regular file: {path}")
    if info.st_size > max_bytes:
        raise ValueError(f"refusing to hash file larger than {max_bytes} bytes: {path}")


def digest(path: str, max_bytes: int = MAX_DIGEST_BYTES) -> str:
    target = Path(path)
    _regular_file(target, max_bytes)
    h = hashlib.sha256()
    with target.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create(paths, output: str) -> None:
    data = {str(Path(p)): digest(p) for p in paths}
    atomic_write(output, (json.dumps(data, indent=2) + "\n").encode(), 0o600)


def verify(baseline: str):
    baseline_path = Path(baseline)
    _regular_file(baseline_path, MAX_BASELINE_BYTES)
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON object")
    if len(data) > MAX_BASELINE_ENTRIES:
        raise ValueError(f"baseline contains more than {MAX_BASELINE_ENTRIES} entries")
    for path, expected in data.items():
        if not isinstance(path, str) or not isinstance(expected, str):
            raise ValueError("baseline keys and digests must be strings")
    return [(path, digest(path) == expected) for path, expected in data.items()]
