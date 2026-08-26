"""Command-line interface for scanning shell history for leaked secrets."""

import argparse
import sys
from pathlib import Path
from pydantic import ValidationError

from secrethunter.detector import scan_history
from secrethunter.models import ScanTarget

DEFAULT_HISTORY_FILES = ("~/.bash_history", "~/.zsh_history")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-hunter",
        description="Scan shell history for accidentally leaked secrets.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="History file to scan (default: ~/.bash_history, then ~/.zsh_history)",
    )
    return parser

def resolve_default_path() -> Path:
    for candidate in DEFAULT_HISTORY_FILES:
        path = Path(candidate).expanduser()
        if path.exists():
            return path
    raise FileNotFoundError(
        f"No history file found in default locations: {DEFAULT_HISTORY_FILES}"
    )

def build_report(target: ScanTarget) -> str:
    lines = target.path.read_text(errors="ignore").splitlines()
    findings = scan_history(lines)

    if not findings:
        return f"No likely secrets found in {target.path} ({len(lines)} lines scanned)."

    report_lines = [f"Found {len(findings)} potential secret(s) in {target.path}:\n"]
    for f in findings:
        report_lines.append(f"  [{f.severity.value}] line {f.line_number}: {f.reason}")
        report_lines.append(f"    {f.line.strip()[:100]}")
    return "\n".join(report_lines)

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        path = Path(args.path).expanduser() if args.path else resolve_default_path()
        target = ScanTarget(path=path)
    except (ValidationError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(build_report(target))


if __name__ == "__main__":
    main()
