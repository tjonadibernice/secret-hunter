"""Detect likely-leaked secrets in shell history lines.

Two detection strategies, combined:
1. Known patterns — recognizable formats for specific providers (AWS, GitHub,
   Slack) and generic credential-in-URL patterns.
2. Shannon entropy — a generic fallback that flags long, high-randomness
   strings assigned to a variable, since most secrets "look random" even
   when they don't match a known provider format.
"""

import math
import re
from dataclasses import dataclass
from enum import Enum

MIN_ENTROPY_LENGTH = 20
ENTROPY_THRESHOLD = 4.0  # bits per character; typical English text is ~4.0-4.5,
                          # random base64/hex secrets are usually 4.5+


class Severity(str, Enum):
    HIGH = "HIGH"      # matched a known, specific secret format
    MEDIUM = "MEDIUM"   # high-entropy string, likely a secret but unconfirmed


@dataclass
class Finding:
    line_number: int
    line: str
    reason: str
    severity: Severity


# (name, compiled pattern) — patterns are intentionally specific to minimize
# false positives; a real secret usually has a recognizable prefix.
KNOWN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Personal Access Token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub Fine-Grained Token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Generic Credential in URL", re.compile(r"://[^\s:@/]+:[^\s:@/]+@")),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
]

# Commands that commonly carry secrets as arguments — used to scope the
# entropy check so we don't flag every long random-looking word in history.
SECRET_BEARING_PREFIXES = ("export ", "set ", "curl ", "git clone ")


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string, in bits per character."""
    if not s:
        return 0.0
    freq = {ch: s.count(ch) for ch in set(s)}
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def find_known_patterns(line: str) -> list[Finding]:
    findings = []
    for name, pattern in KNOWN_PATTERNS:
        if pattern.search(line):
            findings.append(
                Finding(line_number=0, line=line, reason=name, severity=Severity.HIGH)
            )
    return findings


def find_high_entropy_tokens(line: str) -> list[Finding]:
    if not line.startswith(SECRET_BEARING_PREFIXES):
        return []

    findings = []
    # Look at tokens that appear after an '=' (e.g. API_KEY=abc123...)
    for match in re.finditer(rf"=([A-Za-z0-9+/_-]{{{MIN_ENTROPY_LENGTH},}})", line):
        token = match.group(1)
        entropy = shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    line_number=0,
                    line=line,
                    reason=f"High-entropy value ({entropy:.1f} bits/char)",
                    severity=Severity.MEDIUM,
                )
            )
    return findings


def scan_line(line: str) -> list[Finding]:
    """Run all detectors against a single history line."""
    if line.rstrip().endswith("# secret-hunter-ignore"):
        return []
    return find_known_patterns(line) + find_high_entropy_tokens(line)


def scan_history(lines: list[str]) -> list[Finding]:
    """Scan every line of shell history and return all findings, in order."""
    all_findings = []
    for i, line in enumerate(lines, start=1):
        for finding in scan_line(line):
            finding.line_number = i
            all_findings.append(finding)
    return all_findings
