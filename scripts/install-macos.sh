#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
command -v python3 >/dev/null || { echo 'python3 is required'; exit 1; }
python3 -m venv "$root/.venv"
"$root/.venv/bin/pip" install --upgrade pip
"$root/.venv/bin/pip" install -e "$root"
printf 'Installed SafeStack Sentinel in %s/.venv\n' "$root"
