"""Command-line interface for ARD Guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .core import ScanReport, scan_document


def _load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _render_text(report: ScanReport) -> str:
    if not report.findings:
        return "ARD Guard: PASS — no policy findings"

    lines = [
        f"ARD Guard: {len(report.findings)} finding(s), risk={report.risk_score}/100, "
        f"highest={report.highest_severity.value if report.highest_severity else 'none'}"
    ]
    for finding in report.findings:
        lines.append(
            f"[{finding.severity.value.upper():8}] {finding.rule_id} {finding.path}: {finding.message}"
        )
        if finding.evidence:
            lines.append(f"           evidence: {finding.evidence}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ard-guard",
        description="Pre-install provenance and policy firewall for agentic resources.",
    )
    parser.add_argument("--version", action="version", version=f"ard-guard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan an ARD / AI Catalog JSON document")
    scan.add_argument("path", type=Path, help="JSON file to scan")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command != "scan":
        return 2

    try:
        document = _load_json(args.path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"ard-guard: unable to read valid JSON: {exc}", file=sys.stderr)
        return 2

    report = scan_document(document)
    if args.format == "json":
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_text(report))
    return 1 if report.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
