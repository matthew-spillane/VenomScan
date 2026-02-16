from __future__ import annotations

from typing import Any
from urllib import error, request

KEY_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def probe_url(url: str, timeout: int = 8) -> dict[str, Any]:
    req = request.Request(url, method="GET", headers={"User-Agent": "venomscan/0.1"})
    try:
        with request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw_headers = dict(resp.headers.items())
            headers = normalize_headers(raw_headers)
            return {
                "url": url,
                "ok": True,
                "status_code": resp.status,
                "server": headers.get("server"),
                "security_headers": {h: headers.get(h) for h in KEY_SECURITY_HEADERS},
                "error": None,
            }
    except error.HTTPError as exc:
        headers = normalize_headers(dict(exc.headers.items())) if exc.headers else {}
        return {
            "url": url,
            "ok": False,
            "status_code": exc.code,
            "server": headers.get("server"),
            "security_headers": {h: headers.get(h) for h in KEY_SECURITY_HEADERS},
            "error": str(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "url": url,
            "ok": False,
            "status_code": None,
            "server": None,
            "security_headers": {h: None for h in KEY_SECURITY_HEADERS},
            "error": str(exc),
        }


def probe_http_https(target: str, timeout: int = 8) -> dict[str, Any]:
    return {
        "http": probe_url(f"http://{target}/", timeout=timeout),
        "https": probe_url(f"https://{target}/", timeout=timeout),
    }
