from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def serve(directory: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError(f"Report directory does not exist: {root}")

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

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
