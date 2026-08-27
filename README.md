# Secret Hunter

A CLI tool that scans your shell history for accidentally leaked secrets — API keys, tokens, and credentials typed directly into commands like `export`, `curl`, or `git clone`.

## Why this exists

Most secret-scanning tools (gitleaks, truffleHog, detect-secrets) only look at files tracked in git. But a very common way secrets actually leak is different: a developer types `export API_KEY=sk-...` or `curl https://user:pass@api.example.com` directly into their terminal — and that command sits in `~/.bash_history` or `~/.zsh_history` indefinitely, readable by anyone with access to the machine, and never touched by any repo-based scanner. Secret Hunter targets that specific, underserved gap.

## How it works

Two detection strategies, combined:
1. **Known patterns** — regex matching for recognizable secret formats (AWS keys, GitHub tokens, Slack tokens, Anthropic/OpenAI API keys, credentials embedded in URLs)
2. **Shannon entropy** — flags high-randomness strings assigned to a variable in secret-bearing commands (`export`, `set`, `curl`, `git clone`), catching secrets that don't match a known provider format

## Installation

```bash
git clone https://github.com/<your-username>/secret-hunter.git
cd secret-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

Scan your default shell history:
```bash
secret-hunter
```

Scan a specific file:
```bash
secret-hunter /path/to/history/file
```

Scan multiple files at once:
```bash
secret-hunter ~/.bash_history ~/.zsh_history
```

Get JSON output (useful for piping into other tools):
```bash
secret-hunter --json
```

Suppress a known false positive by appending a marker comment to the line in your history file:
```
export SOME_LONG_RANDOM_VALUE=abc123...  # secret-hunter-ignore
```

Example output:
```
Found 3 potential secret(s) in /home/user/.bash_history:

  [HIGH] line 42: AWS Access Key ID
    export AWS_ACCESS_KEY_ID=AKIA...
  [MEDIUM] line 108: High-entropy value (5.0 bits/char)
    export SECRET=aB3xQ9zM2p...
```

## Running tests

```bash
pytest -v
```

## Tech stack

Python, [pydantic](https://docs.pydantic.dev/) for input validation, [pytest](https://docs.pytest.org/) for testing.

## Limitations

- Regex-based detection has known false-negative risk for secret formats not in `KNOWN_PATTERNS`
- Entropy-based detection can produce false positives on legitimately random values (e.g. UUIDs, hashes) assigned via a matched command prefix
- Does not modify or redact your history file — read-only reporting tool
