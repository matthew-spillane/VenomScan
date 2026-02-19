from __future__ import annotations

from pathlib import Path

from venomscan.config import load_config, resolve_runtime_config


def test_load_config_valid(tmp_path: Path) -> None:
    config_path = tmp_path / "scan.yaml"
    config_path.write_text(
        """
targets:
  - example.com
scanners:
  dns: true
  http: false
  tls: true
  nmap: false
output:
  format: html
  out_dir: reports-custom
timeouts:
  http:
    timeout: 5
  tls:
    timeout: 9
""".strip(),
        encoding="utf-8",
    )

    cfg = load_config(config_path)
    assert cfg["targets"] == ["example.com"]
    assert cfg["output"]["format"] == "html"
    assert cfg["timeouts"]["http"]["timeout"] == 5


def test_runtime_override_precedence() -> None:
    cfg = {
        "targets": ["example.com"],
        "output": {"format": "html", "out_dir": "from-config"},
        "timeouts": {"http": {"timeout": 4}, "tls": {"timeout": 7}},
    }

    resolved = resolve_runtime_config(
        target="127.0.0.1",
        raw_config=cfg,
        cli_out_dir="cli-out",
        cli_format="json",
        cli_timeout=11,
        cli_nmap_args=None,
        cli_no_nmap=False,
        default_nmap_args="-sT",
    )

    assert resolved["targets"] == ["127.0.0.1", "example.com"]
    assert resolved["out_dir"] == "cli-out"
    assert resolved["format"] == "json"
    assert resolved["timeout"] == 11
    assert resolved["http_timeout"] == 4
    assert resolved["tls_timeout"] == 7


def test_runtime_nmap_flag_overrides_config() -> None:
    cfg = {"scanners": {"nmap": True}}
    resolved = resolve_runtime_config(
        target="127.0.0.1",
        raw_config=cfg,
        cli_out_dir=None,
        cli_format=None,
        cli_timeout=None,
        cli_nmap_args=None,
        cli_no_nmap=True,
        default_nmap_args="-sT",
    )

    assert resolved["enable_nmap"] is False
