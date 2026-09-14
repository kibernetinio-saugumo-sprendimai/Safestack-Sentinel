# Plugins

Plugins are opt-in Python files in a directory passed with `--plugins-dir`.
Each file exports `run()` and returns a `Finding` or a list of findings. Review
plugin source first because it runs with the same permissions as Sentinel.

```python
from sentinel.model import Finding
def run():
    return Finding("example", "low", "pass", "Example check")
```
