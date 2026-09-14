#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 -m venv "$root/.venv"
"$root/.venv/bin/python" -m pip install --upgrade pip
"$root/.venv/bin/pip" install -e "$root"
printf 'Installed SafeStack Sentinel in %s/.venv\n' "$root"
