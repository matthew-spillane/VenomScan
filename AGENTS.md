# AGENTS.md

## Setup commands
```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Run commands
```bash
venomscan example.com
venomscan 127.0.0.1 --format both --out-dir ./reports
python -m venomscan.cli example.com
```

## Test commands
```bash
pytest -q
```

## Formatting and linting
- Use **black** for formatting.
- Use **ruff** for linting.

```bash
black .
ruff check .
```
