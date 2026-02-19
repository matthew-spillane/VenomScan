# Contributing

Thank you for your interest in contributing to VenomScan.

## Development Setup

```bash
git clone <repo-url>
cd VenomScan
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Local Checks

Run all checks before opening a PR:

```bash
ruff check .
black .
pytest -q
```

## Submitting a Pull Request

1. Create a branch from the latest main branch.
2. Keep changes scoped and well-documented.
3. Ensure linting and tests pass locally.
4. Open a pull request with a clear summary and testing notes.
