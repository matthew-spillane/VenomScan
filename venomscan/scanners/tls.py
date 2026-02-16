from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def _parse_cert_time(value: str | None) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )  # noqa: UP017
    except ValueError:
        return value
    return dt.isoformat()


def get_tls_info(host: str, timeout: int = 8, port: int = 443) -> dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                sans = [entry[1] for entry in cert.get("subjectAltName", []) if len(entry) >= 2]
                subject = cert.get("subject", ())
                issuer = cert.get("issuer", ())
                return {
                    "ok": True,
                    "subject": subject,
                    "issuer": issuer,
                    "san": sans,
                    "not_before": _parse_cert_time(cert.get("notBefore")),
                    "not_after": _parse_cert_time(cert.get("notAfter")),
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                    "error": None,
                }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "subject": None,
            "issuer": None,
            "san": [],
            "not_before": None,
            "not_after": None,
            "protocol": None,
            "cipher": None,
            "error": str(exc),
        }
