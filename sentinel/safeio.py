"""Small helpers for writing audit artifacts without following symlinks."""
import os
import tempfile
from pathlib import Path

def _parent(path: str) -> Path:
    parent = Path(path).expanduser().parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise ValueError("artifact parent must not be a symlink")
    return parent.resolve(strict=True)

def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    target = Path(path).expanduser()
    parent = _parent(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, parent / target.name)
    except Exception:
        try: os.unlink(temporary)
        except OSError: pass
        raise

def append_no_follow(path: str, data: bytes, mode: int = 0o600) -> None:
    target = Path(path).expanduser()
    parent = _parent(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(parent / target.name, flags, mode)
    try:
        with os.fdopen(fd, "ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try: os.close(fd)
        except OSError: pass
        raise
