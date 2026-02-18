from __future__ import annotations

from datetime import datetime
from enum import Enum
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
from venomscan.severity import build_findings, summarize_severity

app = typer.Typer(add_completion=False, help="Safe recon scanner prototype")
console = Console()


class OutputFormat(str, Enum):
    JSON = "json"
    HTML = "html"
    BOTH = "both"


@app.command()
def main(
    target: str = typer.Argument(..., help="Domain, hostname, or IP target"),
    out_dir: Path = typer.Option(  # noqa: B008
        Path("reports"), "--out-dir", help="Directory for reports"
    ),
    format: OutputFormat = typer.Option(  # noqa: B008
        OutputFormat.BOTH,
        "--format",
        help="Output format: json, html, or both",
    ),
    timeout: int = typer.Option(8, "--timeout", min=1, max=120),  # noqa: B008
    nmap_args: str = typer.Option(  # noqa: B008
        DEFAULT_NMAP_ARGS, "--nmap-args", help="Advanced nmap args"
    ),
    no_nmap: bool = typer.Option(False, "--no-nmap", help="Skip nmap scan stage"),  # noqa: B008
) -> None:
    scanned_at = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{target.replace('/', '_')}_{scanned_at}"

    console.print(Panel.fit(f"[bold red]venomscan[/bold red] scanning [bold]{target}[/bold]"))

    console.print("🔎 [bold]DNS[/bold] resolving target and records...")
    dns_data = resolve_dns(target, timeout=timeout)

    if no_nmap:
        console.print("⏭️  [yellow]Nmap skipped[/yellow] (--no-nmap)")
        nmap_data = {
            "available": False,
            "skipped": True,
            "error": "Skipped due to --no-nmap flag.",
            "command": None,
            "services": [],
            "stdout": "",
            "stderr": "",
        }
    else:
        console.print("🧭 [bold]Nmap[/bold] running safe TCP service scan...")
        nmap_data = run_nmap(target, timeout=max(timeout * 4, 20), nmap_args=nmap_args)

    console.print("🌐 [bold]HTTP(S)[/bold] probing root endpoints...")
    http_data = probe_http_https(target, timeout=timeout)

    if http_data["https"]["ok"]:
        console.print("🔐 [bold]TLS[/bold] collecting certificate/session metadata...")
        tls_data = get_tls_info(target, timeout=timeout)
    else:
        console.print("⚠️  [yellow]TLS skipped[/yellow] (HTTPS not reachable)")
        tls_data = {"ok": False, "error": "HTTPS probe failed; TLS details unavailable."}

    report = {
        "target": target,
        "scanned_at": datetime.now().isoformat(),
        "settings": {
            "timeout": timeout,
            "nmap_args": nmap_args,
            "no_nmap": no_nmap,
        },
        "dns": dns_data,
        "nmap": nmap_data,
        "http": http_data,
        "tls": tls_data,
    }

    findings = build_findings(report)
    severity_counts = summarize_severity(findings)
    report["severity_summary"] = severity_counts

    _print_summary(report)

    outputs: list[Path] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    if format in (OutputFormat.JSON, OutputFormat.BOTH):
        json_path = out_dir / f"{base_name}.json"
        write_json_report(json_path, report)
        outputs.append(json_path)
    if format in (OutputFormat.HTML, OutputFormat.BOTH):
        html_path = out_dir / f"{base_name}.html"
        render_html_report(html_path, report)
        outputs.append(html_path)

    for out in outputs:
        console.print(f"[green]Saved:[/green] {out}")


def _sev_text_label(level: str) -> str:
    palette = {
        "high": "[bold red]HIGH[/bold red]",
        "medium": "[bold yellow]MEDIUM[/bold yellow]",
        "low": "[bold cyan]LOW[/bold cyan]",
    }
    return palette.get(level, "LOW")


def _print_summary(report: dict) -> None:
    dns_data = report["dns"]
    nmap_data = report["nmap"]
    http_data = report["http"]
    tls_data = report["tls"]
    findings = report.get("findings", [])
    sev = report.get("severity_summary", {"high": 0, "medium": 0, "low": 0})

    table = Table(title="Recon Summary")
    table.add_column("Section", style="red")
    table.add_column("Details", overflow="fold")

    dns_details = (
        f"resolved_ip={dns_data.get('resolved_ip') or 'n/a'} "
        f"errors={len(dns_data.get('errors', []))}"
    )
    table.add_row("🔎 DNS", dns_details)
    table.add_row(
        "🧭 Nmap",
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
    table.add_row("🌐 HTTP(S)", http_details)
    table.add_row("🔐 TLS", "ok" if tls_data.get("ok") else tls_data.get("error", "unavailable"))

    console.print(table)

    finding_table = Table(title="Findings by Severity")
    finding_table.add_column("Severity")
    finding_table.add_column("Title")
    finding_table.add_column("Details", overflow="fold")

    for finding in findings[:12]:
        finding_table.add_row(
            _sev_text_label(finding.get("severity", "low")),
            finding.get("title", "n/a"),
            finding.get("details", ""),
        )
    if not findings:
        finding_table.add_row(
            "[cyan]LOW[/cyan]", "No notable findings", "No findings were generated"
        )

    console.print(finding_table)

    final = Panel.fit(
        "\n".join(
            [
                "[bold]Scan complete[/bold]",
                f"[red]High:[/red] {sev['high']}  "
                f"[yellow]Medium:[/yellow] {sev['medium']}  [cyan]Low:[/cyan] {sev['low']}",
                f"Total findings: {len(findings)}",
            ]
        ),
        border_style="red" if sev["high"] else "yellow" if sev["medium"] else "green",
        title="📌 Final Summary",
    )
    console.print(final)


if __name__ == "__main__":
    app()
