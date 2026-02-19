from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from venomscan.config import load_config, resolve_runtime_config
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
    out_dir: Path | None = typer.Option(  # noqa: B008
        None, "--out-dir", help="Directory for reports"
    ),
    format: OutputFormat | None = typer.Option(  # noqa: B008
        None,
        "--format",
        help="Output format: json, html, or both",
    ),
    timeout: int | None = typer.Option(None, "--timeout", min=1, max=120),  # noqa: B008
    nmap_args: str | None = typer.Option(
        None, "--nmap-args", help="Advanced nmap args"
    ),  # noqa: B008
    no_nmap: bool = typer.Option(False, "--no-nmap", help="Skip nmap scan stage"),  # noqa: B008
    config: Path | None = typer.Option(  # noqa: B008
        None, "--config", help="Path to YAML config file"
    ),
) -> None:
    raw_config: dict[str, Any] = {}
    if config:
        try:
            raw_config = load_config(config)
        except (RuntimeError, ValueError) as exc:
            raise typer.BadParameter(str(exc), param_hint="--config") from exc

    resolved = resolve_runtime_config(
        target=target,
        raw_config=raw_config,
        cli_out_dir=str(out_dir) if out_dir else None,
        cli_format=format.value if format else None,
        cli_timeout=timeout,
        cli_nmap_args=nmap_args,
        cli_no_nmap=no_nmap,
        default_nmap_args=DEFAULT_NMAP_ARGS,
    )

    for current_target in resolved["targets"]:
        _run_scan(
            target=str(current_target),
            out_dir=Path(str(resolved["out_dir"])),
            format=OutputFormat(str(resolved["format"])),
            timeout=int(resolved["timeout"]),
            http_timeout=int(resolved["http_timeout"]),
            tls_timeout=int(resolved["tls_timeout"]),
            nmap_args=str(resolved["nmap_args"]),
            enable_dns=bool(resolved["enable_dns"]),
            enable_http=bool(resolved["enable_http"]),
            enable_tls=bool(resolved["enable_tls"]),
            enable_nmap=bool(resolved["enable_nmap"]),
            no_nmap=no_nmap,
        )


def _run_scan(
    target: str,
    out_dir: Path,
    format: OutputFormat,
    timeout: int,
    http_timeout: int,
    tls_timeout: int,
    nmap_args: str,
    enable_dns: bool,
    enable_http: bool,
    enable_tls: bool,
    enable_nmap: bool,
    no_nmap: bool,
) -> None:
    scanned_at = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{target.replace('/', '_')}_{scanned_at}"

    console.print(Panel.fit(f"[bold red]venomscan[/bold red] scanning [bold]{target}[/bold]"))

    if enable_dns:
        console.print("🔎 [bold]DNS[/bold] resolving target and records...")
        dns_data = resolve_dns(target, timeout=timeout)
    else:
        dns_data = {
            "target": target,
            "resolved_ip": None,
            "records": {},
            "errors": ["DNS scanner disabled by config"],
        }

    if enable_nmap:
        console.print("🧭 [bold]Nmap[/bold] running safe TCP service scan...")
        nmap_data = run_nmap(target, timeout=max(timeout * 4, 20), nmap_args=nmap_args)
    else:
        if no_nmap:
            console.print("⏭️  [yellow]Nmap skipped[/yellow] (--no-nmap)")
        nmap_data = {
            "available": False,
            "skipped": True,
            "error": "Skipped due to scanner settings.",
            "command": None,
            "services": [],
            "stdout": "",
            "stderr": "",
        }

    if enable_http:
        console.print("🌐 [bold]HTTP(S)[/bold] probing root endpoints...")
        http_data = probe_http_https(target, timeout=http_timeout)
    else:
        http_data = {
            "http": {
                "ok": False,
                "status_code": None,
                "server": None,
                "security_headers": {},
                "error": "HTTP scanner disabled by config",
            },
            "https": {
                "ok": False,
                "status_code": None,
                "server": None,
                "security_headers": {},
                "error": "HTTP scanner disabled by config",
            },
        }

    if enable_tls and http_data.get("https", {}).get("ok"):
        console.print("🔐 [bold]TLS[/bold] collecting certificate/session metadata...")
        tls_data = get_tls_info(target, timeout=tls_timeout)
    elif not enable_tls:
        tls_data = {"ok": False, "error": "TLS scanner disabled by config."}
    else:
        console.print("⚠️  [yellow]TLS skipped[/yellow] (HTTPS not reachable)")
        tls_data = {"ok": False, "error": "HTTPS probe failed; TLS details unavailable."}

    report = {
        "target": target,
        "scanned_at": datetime.now().isoformat(),
        "settings": {
            "timeout": timeout,
            "http_timeout": http_timeout,
            "tls_timeout": tls_timeout,
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
