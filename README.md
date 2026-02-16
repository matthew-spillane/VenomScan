# venomscan (v0.1 prototype)

`venomscan` is a safe recon CLI for domains, hostnames, and IPs.

## Features
- DNS resolution + common DNS records (`A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`)
- Nmap safe fast scan (top 1000 TCP ports + service/version detection)
- HTTP(S) probe (`/`) with status, server header, and key security headers
- TLS certificate + session metadata when HTTPS is available
- Output formats:
  - Rich terminal summary with severity indicators
  - JSON report with per-finding severity
  - HTML report (dark theme + red accents + severity badges)

> ⚠️ Recon only. No exploitation functionality is included.

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
venomscan <target> [options]
```

### Examples
```bash
venomscan example.com
venomscan 127.0.0.1 --timeout 6
venomscan example.com --out-dir ./reports --format both
venomscan example.com --nmap-args "-sT -Pn --top-ports 1000 -sV"
```

### Options
- `--out-dir PATH` (default: `./reports`)
- `--format [json|html|both]` (default: `both`)
- `--timeout INTEGER` (default: `8`)
- `--nmap-args TEXT` (advanced override)
- `--no-nmap` (skip nmap stage for constrained environments)

## Output naming
Reports are named:

- `<target>_<YYYYmmdd_HHMMSS>.json`
- `<target>_<YYYYmmdd_HHMMSS>.html`

## Terminal screenshot placeholder
![terminal output placeholder](docs/screenshots/terminal-placeholder.png)

## HTML screenshot placeholder
![html report placeholder](docs/screenshots/html-placeholder.png)

## Dev checks
```bash
ruff check .
black --check .
pytest -q
```
