from venomscan.scanners.dns import is_ip_target
from venomscan.scanners.http import normalize_headers
from venomscan.scanners.nmap import parse_nmap_output
from venomscan.scanners.tls import _parse_cert_time


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
