import os
import stat
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def _is_safe_dashboard_path(root: Path, path: Path) -> bool:
    root = root.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError:
        try:
            relative = path.resolve(strict=False).relative_to(root)
            path = root / relative
        except ValueError:
            return False
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return False
    try:
        path.resolve(strict=False).relative_to(root)
    except ValueError:
        return False
    return True


def _open_dashboard_file(root: Path, path: Path):
    if not _is_safe_dashboard_path(root, path):
        raise PermissionError("symlink traversal is not allowed")
    relative = path.relative_to(root.resolve())
    parts = list(relative.parts)
    if not parts:
        parts = ["index.html"]
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(root, os.O_RDONLY)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | nofollow, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
            if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
                raise FileNotFoundError(str(path))
        fd = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise IsADirectoryError(str(path))
    return os.fdopen(fd, "rb")


def serve(directory: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError(f"Report directory does not exist: {root}")

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def translate_path(self, path):
            translated = Path(super().translate_path(path))
            self._sentinel_forbidden = not _is_safe_dashboard_path(root, translated)
            return str(translated)

        def send_head(self):
            path = Path(self.translate_path(self.path))
            if getattr(self, "_sentinel_forbidden", False):
                self.send_error(403, "Symlink traversal is not allowed")
                return None
            try:
                stream = _open_dashboard_file(root, path)
            except FileNotFoundError:
                self.send_error(404, "File not found")
                return None
            except IsADirectoryError:
                self.send_error(403, "Directory listing is disabled")
                return None
            except OSError:
                self.send_error(403, "File cannot be served")
                return None
            info = os.fstat(stream.fileno())
            self.send_response(200)
            self.send_header("Content-type", self.guess_type(str(path)))
            self.send_header("Content-Length", str(info.st_size))
            self.send_header("Last-Modified", self.date_time_string(info.st_mtime))
            self.end_headers()
            return stream

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Sentinel dashboard: http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
