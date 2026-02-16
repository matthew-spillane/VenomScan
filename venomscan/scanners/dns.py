from __future__ import annotations

import ipaddress
import socket
from typing import Any

RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT")

try:
    import dns.exception
    import dns.resolver
except ModuleNotFoundError:  # pragma: no cover - environment fallback
    dns = None


def is_ip_target(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return False
    return True


def resolve_dns(target: str, timeout: int = 8) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target": target,
        "resolved_ip": None,
        "records": {rtype: [] for rtype in RECORD_TYPES},
        "errors": [],
    }

    try:
        if is_ip_target(target):
            result["resolved_ip"] = target
        else:
            result["resolved_ip"] = socket.gethostbyname(target)
    except socket.gaierror as exc:
        result["errors"].append(f"Resolution failed: {exc}")

    if is_ip_target(target):
        return result

    if dns is None:
        result["errors"].append("dnspython not installed; detailed DNS records unavailable")
        return result

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype)
            parsed = [record.to_text() for record in answers]
            result["records"][rtype] = parsed
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except dns.exception.DNSException as exc:
            result["errors"].append(f"{rtype} lookup failed: {exc}")

    return result
