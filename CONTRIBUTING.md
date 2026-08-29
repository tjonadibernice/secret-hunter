# Contributing

Thanks for your interest in this project! Here's how to get set up.

## Development setup

```bash
git clone https://github.com/tjonadibernice/secret-hunter.git
cd secret-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running checks before submitting

```bash
ruff check .        # lint
mypy secrethunter    # type-check
pytest -v            # tests
```

All three must pass before a PR can be merged (enforced via CI).

## Workflow

1. Create a branch: `git checkout -b your-feature-name`
2. Make your changes, with tests for any new behavior
3. Run the checks above locally
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/) style, e.g. `feat: add X`, `fix: correct Y`
5. Push and open a Pull Request — the PR template will guide you through what to include

## Reporting issues

Open a GitHub Issue with a clear description and, if possible, steps to reproduce.
