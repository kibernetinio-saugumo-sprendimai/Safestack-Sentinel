# Alerts and exports

`audit --pdf report.pdf` creates a dependency-free report. `audit --history
~/.safestack-sentinel/history.jsonl` appends JSONL records; `history --path ...`
prints scores. Telegram requires `--telegram` plus its two environment variables.
