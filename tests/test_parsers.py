from datetime import datetime, timedelta, timezone

from venomscan.scanners.dns import is_ip_target
from venomscan.scanners.http import normalize_headers
from venomscan.scanners.nmap import parse_nmap_output
from venomscan.scanners.tls import _parse_cert_time
from venomscan.severity import (
    build_findings,
    severity_for_missing_header,
    severity_for_port,
    severity_for_tls_window,
)


def test_is_ip_target() -> None:
    assert is_ip_target("127.0.0.1")
    assert is_ip_target("2001:db8::1")
    assert not is_ip_target("example.com")


def test_parse_nmap_output() -> None:
    sample = """
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    nginx 1.24
443/tcp  closed https
"""
    services = parse_nmap_output(sample)
    assert len(services) == 2
    assert services[0]["port"] == "22/tcp"
    assert services[1]["service"] == "http"


def test_normalize_headers() -> None:
    headers = {"Server": "nginx", "X-Frame-Options": "DENY"}
    normalized = normalize_headers(headers)
    assert normalized["server"] == "nginx"
    assert normalized["x-frame-options"] == "DENY"


def test_parse_cert_time() -> None:
    assert _parse_cert_time("Jan 01 00:00:00 2025 GMT").startswith("2025-01-01T00:00:00")
    assert _parse_cert_time(None) is None


def test_severity_port_mapping() -> None:
    assert severity_for_port("22/tcp")[0] == "high"
    assert severity_for_port("8080/tcp")[0] == "medium"
    assert severity_for_port("80/tcp")[0] == "low"


def test_header_severity() -> None:
    assert severity_for_missing_header("content-security-policy") == "medium"
    assert severity_for_missing_header("permissions-policy") == "low"


def test_tls_window_severity() -> None:
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    soon = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    later = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

    assert severity_for_tls_window(expired)[0] == "high"
    assert severity_for_tls_window(soon)[0] == "high"
    assert severity_for_tls_window(later)[0] == "low"


def test_build_findings_populates_severity() -> None:
    report = {
        "target": "example.com",
        "nmap": {"services": [{"port": "22/tcp", "service": "ssh"}]},
        "http": {
            "https": {"security_headers": {"content-security-policy": None}},
            "http": {"security_headers": {}},
        },
        "tls": {
            "ok": True,
            "not_after": (datetime.now(timezone.utc) + timedelta(days=4)).isoformat(),
        },
    }
    findings = build_findings(report)
    assert findings
    assert any(f["severity"] == "high" for f in findings)
    assert report["nmap"]["services"][0]["severity"] == "high"
