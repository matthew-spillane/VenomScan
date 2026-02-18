# venomscan

![CI](https://github.com/venomscan/venomscan/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

`venomscan` is a safe reconnaissance CLI for domains, hostnames, and IPs.

## Overview

VenomScan provides a focused, non-exploitative recon workflow with terminal and report outputs suitable for both manual review and automation.

## Features

- DNS resolution + common DNS records (`A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`)
- Nmap safe fast scan (top 1000 TCP ports + service/version detection)
- HTTP(S) probe (`/`) with status, server header, and key security headers
- TLS certificate + session metadata when HTTPS is available
- Rich terminal summary with severity indicators
- JSON report with per-finding severity metadata
- HTML report with dark theme and severity badges

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Quick Start

```bash
venomscan example.com
venomscan 127.0.0.1 --no-nmap
venomscan example.com --format both --out-dir ./reports
```

## Usage

```bash
venomscan <target> [options]
```

### Options

- `--out-dir PATH` (default: `./reports`)
- `--format [json|html|both]` (default: `both`)
- `--timeout INTEGER` (default: `8`)
- `--nmap-args TEXT` (advanced override)
- `--no-nmap` (skip nmap stage for constrained environments)

## Safe Targets for Testing

Use only systems you are authorized to assess. Common examples:

- Localhost (`127.0.0.1`)
- Privately owned lab hosts
- Approved internal staging environments
- Public demo targets explicitly intended for testing (with documented permission)

## Security Notice

VenomScan is for authorized security assessment only.

- Do not scan targets without explicit permission.
- Unauthorized scanning may be unlawful and is strictly prohibited.

For vulnerability disclosure guidance, see [SECURITY.md](SECURITY.md).

## Roadmap

- Improve report rendering and accessibility
- Expand normalization and parsing reliability
- Add additional non-invasive recon quality-of-life enhancements

## Development Checks

```bash
ruff check .
black --check .
pytest -q
```

## License

MIT License. See [LICENSE](LICENSE).
