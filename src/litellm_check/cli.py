"""Command line interface: `litellm-check scan <path>`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .report import render_json, render_markdown
from .rules import load_rules
from .scanner import SEVERITY_ORDER, scan_path

FAIL_LEVELS = ["critical", "high", "medium", "low", "info"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="litellm-check",
        description=(
            "Scan a source tree and/or local Python environments for "
            "exposure to the compromised LiteLLM v1.107.0 release "
            "(PyPI / Docker Hub / GHCR, 2026-10-21) and produce an "
            "evidence report. Rules derive solely from LiteLLM's "
            "official incident announcement."
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a directory and report findings.")
    scan.add_argument("path", help="Directory to scan.")
    scan.add_argument(
        "--format", choices=["md", "json"], default="md",
        help="Report format (default: md).",
    )
    scan.add_argument(
        "--out", default=None,
        help="Write the report to this file instead of stdout.",
    )
    scan.add_argument(
        "--fail-on", choices=FAIL_LEVELS + ["none"], default="none",
        help=(
            "Exit with code 1 when any finding is at or above this "
            "severity (for CI). Default: none (always exit 0)."
        ),
    )
    scan.add_argument(
        "--rules", default=None,
        help="Path to an alternate rules JSON file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        target = Path(args.path)
        if not target.is_dir():
            print(f"error: {target} is not a directory", file=sys.stderr)
            return 2
        ruleset = load_rules(args.rules)
        result = scan_path(target, ruleset)
        text = (
            render_json(result, ruleset)
            if args.format == "json"
            else render_markdown(result, ruleset)
        )
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(
                f"litellm-check: {len(result.findings)} finding(s) in "
                f"{result.files_scanned} file(s); report written to {args.out}",
                file=sys.stderr,
            )
        else:
            sys.stdout.write(text)
        if args.fail_on != "none":
            threshold = SEVERITY_ORDER[args.fail_on]
            worst = min(
                (SEVERITY_ORDER.get(f.severity, 99) for f in result.findings),
                default=99,
            )
            if worst <= threshold:
                return 1
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
