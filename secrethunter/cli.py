"""Command-line interface for scanning shell history for leaked secrets."""

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from secrethunter.detector import Finding, scan_history
from secrethunter.models import ScanTarget

DEFAULT_HISTORY_FILES = ("~/.bash_history", "~/.zsh_history")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-hunter",
        description="Scan shell history for accidentally leaked secrets.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=None,
        help="History file(s) to scan (default: ~/.bash_history, then ~/.zsh_history)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON instead of human-readable text",
    )
    return parser


def resolve_default_paths() -> list[Path]:
    for candidate in DEFAULT_HISTORY_FILES:
        path = Path(candidate).expanduser()
        if path.exists():
            return [path]
    raise FileNotFoundError(
        f"No history file found in default locations: {DEFAULT_HISTORY_FILES}"
    )


def findings_to_json(findings_by_file: dict[str, list[Finding]]) -> str:
    payload = {
        str(path): [
            {
                "line_number": f.line_number,
                "line": f.line.strip(),
                "reason": f.reason,
                "severity": f.severity.value,
            }
            for f in findings
        ]
        for path, findings in findings_by_file.items()
    }
    return json.dumps(payload, indent=2)


def build_text_report(findings_by_file: dict[str, list[Finding]]) -> str:
    report_lines = []
    for path, findings in findings_by_file.items():
        if not findings:
            report_lines.append(f"No likely secrets found in {path}.")
            continue
        report_lines.append(f"Found {len(findings)} potential secret(s) in {path}:\n")
        for f in findings:
            report_lines.append(f"  [{f.severity.value}] line {f.line_number}: {f.reason}")
            report_lines.append(f"    {f.line.strip()[:100]}")
        report_lines.append("")
    return "\n".join(report_lines).rstrip()


def scan_targets(targets: list[ScanTarget]) -> dict[str, list[Finding]]:
    """Scan each validated target file and return findings keyed by path."""
    results = {}
    for target in targets:
        lines = target.path.read_text(errors="ignore").splitlines()
        results[str(target.path)] = scan_history(lines)
    return results


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.paths:
            paths = [Path(p).expanduser() for p in args.paths]
        else:
            paths = resolve_default_paths()
        targets = [ScanTarget(path=p) for p in paths]
    except (ValidationError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    findings_by_file = scan_targets(targets)

    if args.json:
        print(findings_to_json(findings_by_file))
    else:
        print(build_text_report(findings_by_file))


if __name__ == "__main__":
    main()
