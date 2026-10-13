import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .model import Finding, score
from .safeio import atomic_write


def build(findings: List[Finding]) -> dict:
    return {
        "schema": "safestack-sentinel/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": score(findings),
        "assessment": ("fail" if any(f.status == "fail" for f in findings) else
                       "review" if not findings or any(f.status in ("unknown", "review") for f in findings) else "pass"),
        "status_counts": {status: sum(f.status == status for f in findings)
                          for status in ("pass", "fail", "review", "unknown")},
        "findings": [f.as_dict() for f in findings],
    }


def write_json(report: dict, path: str) -> None:
    atomic_write(path, (json.dumps(report, indent=2) + "\n").encode(), 0o600)


def write_html(report: dict, path: str) -> None:
    rows = []
    for item in report["findings"]:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(item.get(k, '')))}</td>"
                                     for k in ("check", "severity", "status", "summary", "remediation")) + "</tr>")
    body = "<table><tr><th>Check</th><th>Severity</th><th>Status</th><th>Summary</th><th>Remediation</th></tr>" + "".join(rows) + "</table>"
    atomic_write(path, f"<!doctype html><meta charset='utf-8'><title>SafeStack Sentinel</title><h1>Assessment: {html.escape(report['assessment'])}; score: {report['score']}</h1>{body}".encode(), 0o600)


def plan(report: dict, profile=None) -> dict:
    return {
        "schema": "safestack-sentinel/plan-v1",
        "read_only": True,
        "profile": profile or {"name": "default", "role": "general-purpose host"},
        "actions": [
            {"check": f["check"], "severity": f["severity"], "command": f.get("command", ""), "guidance": f["remediation"]}
            for f in report["findings"] if f["status"] in ("fail", "review", "unknown")
        ],
    }
