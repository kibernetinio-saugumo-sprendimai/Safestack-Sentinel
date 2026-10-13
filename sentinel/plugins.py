"""Opt-in plugin API for local, read-only checks."""
import importlib.util
from pathlib import Path
from typing import List
from .model import Finding

def discover(directory: str = "plugins") -> List[Finding]:
    findings = []
    root = Path(directory).expanduser()
    if root.is_symlink() or not root.is_dir():
        return [Finding("plugins", "medium", "unknown", "Plugin directory is missing or is a symlink")]
    root = root.resolve()
    for path in sorted(root.glob("*.py")):
        if path.name.startswith("_") or path.is_symlink() or not path.is_file():
            continue
        try:
            path.resolve(strict=True).relative_to(root)
        except ValueError:
            continue
        spec = importlib.util.spec_from_file_location("sentinel_plugin_" + path.stem, path)
        if not spec or not spec.loader:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            findings.append(Finding("plugin:" + path.stem, "medium", "unknown",
                                    "Plugin check could not complete", type(exc).__name__))
            continue
        run = getattr(module, "run", None)
        if not callable(run):
            findings.append(Finding("plugin:" + path.stem, "medium", "unknown", "Plugin has no callable run"))
            continue
        try:
            result = run()
        except Exception as exc:
            findings.append(Finding("plugin:" + path.stem, "medium", "unknown",
                                    "Plugin check could not complete", type(exc).__name__))
            continue
        if isinstance(result, Finding):
            result = [result]
        if isinstance(result, list) and all(isinstance(item, Finding) for item in result):
            findings.extend(result)
        else:
            findings.append(Finding("plugin:" + path.stem, "medium", "unknown", "Invalid plugin result"))
    return findings
