from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:
    UTC = datetime.UTC  # type: ignore[attr-defined]
except AttributeError:
    UTC = timezone.utc  # noqa: UP017


HIGH_RISK_PORTS = {
    "21": "FTP exposed",
    "22": "SSH exposed",
    "23": "Telnet exposed",
    "25": "SMTP exposed",
    "3389": "RDP exposed",
    "445": "SMB exposed",
    "1433": "MSSQL exposed",
    "3306": "MySQL exposed",
}
MEDIUM_RISK_PORTS = {
    "53": "DNS service exposed",
    "111": "RPC exposed",
    "139": "NetBIOS exposed",
    "5900": "VNC exposed",
    "8080": "Alt HTTP exposed",
}


def _port_number(port: str) -> str:
    return port.split("/")[0]


def severity_for_port(port: str) -> tuple[str, str]:
    number = _port_number(port)
    if number in HIGH_RISK_PORTS:
        return "high", HIGH_RISK_PORTS[number]
    if number in MEDIUM_RISK_PORTS:
        return "medium", MEDIUM_RISK_PORTS[number]
    if number in {"80", "443"}:
        return "low", "Common web service"
    return "low", "Open port"


def severity_for_missing_header(header: str) -> str:
    medium_headers = {"content-security-policy", "strict-transport-security", "x-frame-options"}
    return "medium" if header in medium_headers else "low"


def severity_for_tls_window(not_after: str | None) -> tuple[str, str]:
    if not not_after:
        return "low", "Certificate expiration unknown"
    try:
        expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except ValueError:
        return "low", "Certificate expiration format unknown"

    now = datetime.now(UTC)
    if expiry < now:
        return "high", "Certificate expired"

    days_remaining = (expiry - now).days
    if days_remaining <= 14:
        return "high", f"Certificate expires soon ({days_remaining} days)"
    if days_remaining <= 45:
        return "medium", f"Certificate expires soon-ish ({days_remaining} days)"
    return "low", f"Certificate valid ({days_remaining} days remaining)"


def build_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for svc in report.get("nmap", {}).get("services", []):
        severity, reason = severity_for_port(svc.get("port", ""))
        finding = {
            "category": "open_port",
            "target": svc.get("port"),
            "severity": severity,
            "title": f"Open port {svc.get('port')}",
            "details": reason,
            "service": svc.get("service"),
        }
        svc["severity"] = severity
        svc["severity_reason"] = reason
        findings.append(finding)

    for scheme, probe in report.get("http", {}).items():
        for header, value in probe.get("security_headers", {}).items():
            if value:
                continue
            severity = severity_for_missing_header(header)
            findings.append(
                {
                    "category": "missing_security_header",
                    "target": scheme,
                    "severity": severity,
                    "title": f"Missing header: {header}",
                    "details": f"{scheme.upper()} response is missing {header}",
                }
            )

    tls = report.get("tls", {})
    if tls.get("ok"):
        severity, reason = severity_for_tls_window(tls.get("not_after"))
        tls["severity"] = severity
        tls["severity_reason"] = reason
        findings.append(
            {
                "category": "tls_certificate",
                "target": report.get("target"),
                "severity": severity,
                "title": "TLS certificate health",
                "details": reason,
            }
        )

    report["findings"] = findings
    return findings


def summarize_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev = finding.get("severity", "low")
        if sev not in counts:
            continue
        counts[sev] += 1
    return counts
