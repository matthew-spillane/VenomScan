from __future__ import annotations
from enum import Enum
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from venomscan.reporting.html_report import render_html_report
from venomscan.reporting.json_report import write_json_report
from venomscan.scanners.dns import resolve_dns
from venomscan.scanners.http import probe_http_https
from venomscan.scanners.nmap import DEFAULT_NMAP_ARGS, run_nmap
from venomscan.scanners.tls import get_tls_info

class OutputFormat(str, Enum):
	json = "json"
	html = "html"
	both = "both"

app = typer.Typer(add_completion=False, help="Safe recon scanner prototype")
console = Console()


@app.command()
def main(
    target: str = typer.Argument(..., help="Domain, hostname, or IP target"),
    out_dir: Path = typer.Option(  # noqa: B008
        Path("reports"), "--out-dir", help="Directory for reports"
    ),
    format: OutputFormat = typer.Option(OutputFormat.both, "--format"),  # noqa: B008
    timeout: int = typer.Option(8, "--timeout", min=1, max=120),  # noqa: B008
    nmap_args: str = typer.Option(  # noqa: B008
        DEFAULT_NMAP_ARGS, "--nmap-args", help="Advanced nmap args"
    ),
) -> None:
    scanned_at = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{target.replace('/', '_')}_{scanned_at}"

    console.print(Panel.fit(f"[bold red]venomscan[/bold red] scanning [bold]{target}[/bold]"))

    dns_data = resolve_dns(target, timeout=timeout)
    nmap_data = run_nmap(target, timeout=max(timeout * 4, 20), nmap_args=nmap_args)
    http_data = probe_http_https(target, timeout=timeout)
    tls_data = (
        get_tls_info(target, timeout=timeout)
        if http_data["https"]["ok"]
        else {"ok": False, "error": "HTTPS probe failed; TLS details unavailable."}
    )

    report = {
        "target": target,
        "scanned_at": datetime.now().isoformat(),
        "settings": {
            "timeout": timeout,
            "nmap_args": nmap_args,
        },
        "dns": dns_data,
        "nmap": nmap_data,
        "http": http_data,
        "tls": tls_data,
    }

    _print_summary(report)

    outputs: list[Path] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    if format in ("json", "both"):
        json_path = out_dir / f"{base_name}.json"
        write_json_report(json_path, report)
        outputs.append(json_path)
    if format in ("html", "both"):
        html_path = out_dir / f"{base_name}.html"
        render_html_report(html_path, report)
        outputs.append(html_path)

    for out in outputs:
        console.print(f"[green]Saved:[/green] {out}")


def _print_summary(report: dict) -> None:
    dns_data = report["dns"]
    nmap_data = report["nmap"]
    http_data = report["http"]
    tls_data = report["tls"]

    table = Table(title="Recon Summary")
    table.add_column("Section", style="red")
    table.add_column("Details", overflow="fold")

    dns_details = (
        f"resolved_ip={dns_data.get('resolved_ip') or 'n/a'} "
        f"errors={len(dns_data.get('errors', []))}"
    )
    table.add_row("DNS", dns_details)
    table.add_row(
        "Nmap",
        (
            f"open_ports={len(nmap_data.get('services', []))}"
            if nmap_data.get("available")
            else f"unavailable ({nmap_data.get('error')})"
        ),
    )
    http_details = (
        f"http={http_data['http'].get('status_code')} "
        f"https={http_data['https'].get('status_code')}"
    )
    table.add_row("HTTP", http_details)
    table.add_row("TLS", "ok" if tls_data.get("ok") else tls_data.get("error", "unavailable"))

    console.print(table)


if __name__ == "__main__":
    app()
