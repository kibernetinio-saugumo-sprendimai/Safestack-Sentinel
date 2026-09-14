import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .model import Finding, score


def build(findings: List[Finding]) -> dict:
    return {
        "schema": "safestack-sentinel/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": score(findings),
        "findings": [f.as_dict() for f in findings],
    }


def write_json(report: dict, path: str) -> None:
    Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def write_html(report: dict, path: str) -> None:
    rows = []
    for item in report["findings"]:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(item.get(k, '')))}</td>"
                                     for k in ("check", "severity", "status", "summary", "remediation")) + "</tr>")
    body = "<table><tr><th>Check</th><th>Severity</th><th>Status</th><th>Summary</th><th>Remediation</th></tr>" + "".join(rows) + "</table>"
    Path(path).write_text(f"<!doctype html><meta charset='utf-8'><title>SafeStack Sentinel</title><h1>Score: {report['score']}</h1>{body}", encoding="utf-8")


def plan(report: dict) -> dict:
    return {
        "schema": "safestack-sentinel/plan-v1",
        "read_only": True,
        "actions": [
            {"check": f["check"], "severity": f["severity"], "command": f.get("command", ""), "guidance": f["remediation"]}
            for f in report["findings"] if f["status"] in ("fail", "review", "unknown")
        ],
    }
