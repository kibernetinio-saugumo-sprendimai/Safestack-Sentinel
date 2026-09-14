import argparse
import json
import sys

from .checks import run_all
from .integrity import create, verify
from .report import build, write_html, write_json
from .report import plan
from .dashboard import serve
from .signing import generate as generate_key, sign as sign_report, verify as verify_signature
from .profiles import load as load_profile
from .plugins import discover
from .history import append as append_history, load as load_history
from .notify import telegram
from .pdf import write_pdf


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="safestack-sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="Run read-only host checks")
    audit.add_argument("--json")
    audit.add_argument("--html")
    audit.add_argument("--pdf")
    audit.add_argument("--plugins-dir")
    audit.add_argument("--history")
    audit.add_argument("--telegram", action="store_true")
    base = sub.add_parser("baseline", help="Manage SHA-256 baselines")
    base_sub = base.add_subparsers(dest="action", required=True)
    create_p = base_sub.add_parser("create")
    create_p.add_argument("output")
    create_p.add_argument("paths", nargs="+")
    verify_p = base_sub.add_parser("verify")
    verify_p.add_argument("baseline")
    sign_p = sub.add_parser("sign")
    sign_p.add_argument("report")
    sign_p.add_argument("signature")
    sign_p.add_argument("private_key")
    key_p = sub.add_parser("keygen")
    key_p.add_argument("private_key")
    key_p.add_argument("public_key")
    sig_p = sub.add_parser("verify-signature")
    sig_p.add_argument("report")
    sig_p.add_argument("signature")
    sig_p.add_argument("public_key")
    plan_p = sub.add_parser("plan", help="Create a non-mutating remediation plan")
    plan_p.add_argument("--json", default="sentinel-plan.json")
    plan_p.add_argument("--profile", default="default")
    fix_p = sub.add_parser("fix", help="Show remediation only; mutation is never performed")
    fix_p.add_argument("--dry-run", action="store_true")
    fix_p.add_argument("--json", default="sentinel-fix-plan.json")
    history_p = sub.add_parser("history", help="Show audit history")
    history_p.add_argument("--path", default="~/.safestack-sentinel/history.jsonl")
    dash_p = sub.add_parser("dashboard", help="Serve reports on localhost")
    dash_p.add_argument("directory", nargs="?", default=".")
    dash_p.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if args.command == "audit":
        findings = run_all() + (discover(args.plugins_dir) if args.plugins_dir else [])
        report = build(findings)
        if args.json:
            write_json(report, args.json)
        if args.html:
            write_html(report, args.html)
        if args.pdf:
            write_pdf(report, args.pdf)
        if args.history:
            append_history(report, args.history)
        if args.telegram:
            print("Telegram notification sent" if telegram(report) else "Telegram notification skipped (credentials missing)")
        print(json.dumps(report, indent=2) if not args.json else f"Score: {report['score']} (report written to {args.json})")
        return 0
    if args.command == "plan":
        load_profile(args.profile)
        report = build(run_all())
        from pathlib import Path
        Path(args.json).write_text(json.dumps(plan(report), indent=2) + "\n", encoding="utf-8")
        print(f"Read-only plan written to {args.json}")
        return 0
    if args.command == "fix":
        if not args.dry_run:
            print("Only --dry-run is supported; no system changes were made.", file=sys.stderr)
            return 2
        report = build(run_all())
        from pathlib import Path
        Path(args.json).write_text(json.dumps(plan(report), indent=2) + "\n", encoding="utf-8")
        print(f"Dry-run fix plan written to {args.json}")
        return 0
    if args.command == "history":
        for row in load_history(args.path):
            print(f"{row.get('generated_at', '?')} score={row.get('score', '?')}")
        return 0
    if args.command == "dashboard":
        serve(args.directory, port=args.port)
        return 0
    if args.command == "keygen":
        generate_key(args.private_key, args.public_key)
        return 0
    if args.command == "sign":
        sign_report(args.report, args.signature, args.private_key)
        return 0
    if args.command == "verify-signature":
        return 0 if verify_signature(args.report, args.signature, args.public_key) else 2
    if args.action == "create":
        create(args.paths, args.output)
        print(f"Baseline written to {args.output}")
        return 0
    results = verify(args.baseline)
    for path, ok in results:
        print(("OK   " if ok else "FAIL ") + path)
    return 0 if all(ok for _, ok in results) else 2
