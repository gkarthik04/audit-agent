"""Command-line entry point: `agent scan <path>` and `agent rules`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from audit_agent import __version__, llm
from audit_agent.engine import scan
from audit_agent.models import Severity
from audit_agent.reporters import REPORTERS, render
from audit_agent.rules import load_rules

SEVERITIES = [s.value for s in Severity]
EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent", description="Architecture-agnostic code-audit agent.")
    parser.add_argument("--version", action="version", version=f"audit-agent {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path", type=Path, help="repository root to scan")
    s.add_argument("-f", "--format", choices=list(REPORTERS), default="text", help="report format (default: text)")
    s.add_argument("-o", "--output", type=Path, help="write the report to a file instead of stdout")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at or above this severity")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    s.add_argument("--disable", action="append", default=[], metavar="ID", help="disable rules by id or prefix, e.g. SLP or GAP001")
    s.add_argument("--no-llm", action="store_true", help="skip the LLM triage pass even if ANTHROPIC_API_KEY is set")
    s.add_argument("--model", help=f"Claude model for triage (default: $AUDIT_AGENT_MODEL or {llm.DEFAULT_MODEL})")

    sub.add_parser("rules", help="list available rules")
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        result = scan(args.path, exclude=args.exclude, disable=set(args.disable),
                      min_severity=Severity(args.min_severity))
    except NotADirectoryError as exc:
        print(f"agent: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.no_llm and llm.is_available():
        print(f"agent: running LLM triage on {min(len(result.findings), llm.MAX_FINDINGS)} findings...", file=sys.stderr)
        result = llm.triage(result, model=args.model)

    report = render(result, args.format)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
        print(f"agent: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(f.severity.rank >= threshold for f in result.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules() -> int:
    seen: set[str] = set()
    for rule in sorted(load_rules(), key=lambda r: r.id):
        if rule.id in seen:  # some ids have a regex flavour and a Python-AST flavour
            continue
        seen.add(rule.id)
        sys.stdout.write(f"{rule.id:8} {rule.severity.value:9} {rule.category.value:9} {rule.title}\n")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # emoji in markdown output on Windows consoles
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return cmd_rules()
