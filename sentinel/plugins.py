"""Opt-in plugin API for local, read-only checks."""
import importlib.util
from pathlib import Path
from typing import List
from .model import Finding

def discover(directory: str = "plugins") -> List[Finding]:
    findings = []
    root = Path(directory)
    if not root.is_dir():
        return findings
    for path in sorted(root.glob("*.py")):
        if path.name.startswith("_") or path.is_symlink():
            continue
        spec = importlib.util.spec_from_file_location("sentinel_plugin_" + path.stem, path)
        if not spec or not spec.loader:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception:
            continue
        run = getattr(module, "run", None)
        if not callable(run):
            continue
        try:
            result = run()
        except Exception:
            continue
        if isinstance(result, Finding):
            result = [result]
        if isinstance(result, list) and all(isinstance(item, Finding) for item in result):
            findings.extend(result)
    return findings
