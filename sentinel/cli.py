import argparse
import json
import sys

from .checks import run_all
from .integrity import create, verify
from .report import build, write_html, write_json


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="safestack-sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="Run read-only host checks")
    audit.add_argument("--json")
    audit.add_argument("--html")
    base = sub.add_parser("baseline", help="Manage SHA-256 baselines")
    base_sub = base.add_subparsers(dest="action", required=True)
    create_p = base_sub.add_parser("create")
    create_p.add_argument("output")
    create_p.add_argument("paths", nargs="+")
    verify_p = base_sub.add_parser("verify")
    verify_p.add_argument("baseline")
    args = parser.parse_args(argv)
    if args.command == "audit":
        report = build(run_all())
        if args.json:
            write_json(report, args.json)
        if args.html:
            write_html(report, args.html)
        print(json.dumps(report, indent=2) if not args.json else f"Score: {report['score']} (report written to {args.json})")
        return 0
    if args.action == "create":
        create(args.paths, args.output)
        print(f"Baseline written to {args.output}")
        return 0
    results = verify(args.baseline)
    for path, ok in results:
        print(("OK   " if ok else "FAIL ") + path)
    return 0 if all(ok for _, ok in results) else 2
