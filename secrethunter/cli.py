"""Command-line interface for scanning shell history for leaked secrets."""

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

import aiofiles
from pydantic import ValidationError

from secrethunter.detector import Finding, scan_history
from secrethunter.models import ScanTarget

DEFAULT_HISTORY_FILES = ("~/.bash_history", "~/.zsh_history")

logger = logging.getLogger("secrethunter")


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
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed progress logging",
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


async def scan_target_async(target: ScanTarget) -> tuple[str, list[Finding]]:
    """Read one file asynchronously and scan it (CPU work stays synchronous)."""
    logger.debug("Reading %s", target.path)
    start = time.monotonic()

    async with aiofiles.open(target.path, mode="r", errors="ignore") as f:
        content = await f.read()

    lines = content.splitlines()
    findings = scan_history(lines)

    elapsed = time.monotonic() - start
    logger.debug(
        "Scanned %s: %d lines, %d finding(s), %.3fs", target.path, len(lines), len(findings), elapsed
    )
    return str(target.path), findings


async def scan_targets(targets: list[ScanTarget]) -> dict[str, list[Finding]]:
    """Scan all target files concurrently and return findings keyed by path."""
    logger.info("Starting scan of %d file(s)", len(targets))
    results = await asyncio.gather(*(scan_target_async(t) for t in targets))
    logger.info("Scan complete")
    return dict(results)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        if args.paths:
            paths = [Path(p).expanduser() for p in args.paths]
        else:
            paths = resolve_default_paths()
        targets = [ScanTarget(path=p) for p in paths]
    except (ValidationError, FileNotFoundError) as e:
        logger.error("%s", e)
        sys.exit(1)

    findings_by_file = asyncio.run(scan_targets(targets))

    if args.json:
        print(findings_to_json(findings_by_file))
    else:
        print(build_text_report(findings_by_file))


if __name__ == "__main__":
    main()
