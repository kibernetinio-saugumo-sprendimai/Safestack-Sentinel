import hashlib
import json
import re
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
    _validate(data)
    atomic_write(output, (json.dumps(data, indent=2) + "\n").encode(), 0o600)


def _unique_object(pairs):
    data = {}
    for path, expected in pairs:
        if path in data:
            raise ValueError(f"duplicate baseline path: {path}")
        data[path] = expected
    return data


def _validate(data):
    if not isinstance(data, dict) or not data:
        raise ValueError("baseline must be a non-empty JSON object")
    if len(data) > MAX_BASELINE_ENTRIES:
        raise ValueError(f"baseline contains more than {MAX_BASELINE_ENTRIES} entries")
    for path, expected in data.items():
        if not isinstance(path, str) or not path or "\x00" in path:
            raise ValueError("baseline paths must be non-empty strings without NUL bytes")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("baseline digests must be 64 lowercase hexadecimal characters")


def verify(baseline: str):
    baseline_path = Path(baseline)
    _regular_file(baseline_path, MAX_BASELINE_BYTES)
    data = json.loads(baseline_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    _validate(data)
    results = []
    for path, expected in data.items():
        try:
            ok = digest(path) == expected
        except OSError:
            ok = False
        results.append((path, ok))
    return results
