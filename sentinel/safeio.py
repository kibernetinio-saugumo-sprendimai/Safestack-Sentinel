"""Small helpers for writing audit artifacts without following symlinks."""
import os
import stat
import tempfile
from pathlib import Path


def _absolute(path: str) -> Path:
    target = Path(path).expanduser()
    return target if target.is_absolute() else Path.cwd() / target


def _parent(path: str) -> Path:
    target = _absolute(path)
    if not target.name:
        raise ValueError("artifact path must include a filename")
    parent = target.parent
    _reject_unsafe_symlink_components(parent)
    if parent.is_symlink():
        raise ValueError("artifact parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    _reject_unsafe_symlink_components(parent)
    if parent.is_symlink():
        raise ValueError("artifact parent must not be a symlink")
    return parent.resolve(strict=True)


def _reject_unsafe_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) and info.st_uid != 0:
            raise ValueError("artifact path must not contain user-owned symlinks")

def atomic_write(path: str, data: bytes, mode: int = 0o600, *, overwrite: bool = True) -> None:
    target = _absolute(path)
    parent = _parent(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, parent / target.name)
        else:
            # Linking publishes the complete file and atomically refuses an
            # existing destination, including one created after preflight.
            os.link(temporary, parent / target.name)
            os.unlink(temporary)
    except Exception:
        try: os.unlink(temporary)
        except OSError: pass
        raise

def append_no_follow(path: str, data: bytes, mode: int = 0o600) -> None:
    target = _absolute(path)
    parent = _parent(path)
    output = parent / target.name
    if output.is_symlink():
        raise ValueError("artifact path must not be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output, flags, mode)
    try:
        with os.fdopen(fd, "ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try: os.close(fd)
        except OSError: pass
        raise
