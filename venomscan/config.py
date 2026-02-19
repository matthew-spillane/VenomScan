from __future__ import annotations

from pathlib import Path
from typing import Any

ALLOWED_FORMATS = {"json", "html", "both"}
SCANNER_KEYS = {"dns", "http", "tls", "nmap"}


def _parse_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.isdigit():
        return int(value)
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _simple_yaml_load(text: str) -> dict[str, Any]:
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(lines):
            return {}, index

        current = lines[index]
        is_list = current.startswith(" " * indent + "- ")
        if is_list:
            items: list[Any] = []
            while index < len(lines):
                line = lines[index]
                if not line.startswith(" " * indent + "- "):
                    break
                item_value = line[indent + 2 :].strip()
                index += 1
                if item_value:
                    items.append(_parse_scalar(item_value))
                else:
                    nested, index = parse_block(index, indent + 2)
                    items.append(nested)
            return items, index

        mapping: dict[str, Any] = {}
        while index < len(lines):
            line = lines[index]
            leading = len(line) - len(line.lstrip(" "))
            if leading < indent:
                break
            if leading > indent:
                break
            if ":" not in line:
                raise ValueError(f"Invalid YAML line: {line}")
            key, raw_value = line[indent:].split(":", 1)
            key = key.strip()
            value = raw_value.strip()
            index += 1
            if value:
                mapping[key] = _parse_scalar(value)
            else:
                nested, index = parse_block(index, indent + 2)
                mapping[key] = nested
        return mapping, index

    parsed, _ = parse_block(0, 0)
    if not isinstance(parsed, dict):
        raise ValueError("Config root must be a mapping/object")
    return parsed


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"Config file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Could not read config file: {exc}") from exc

    try:
        import yaml

        raw = yaml.safe_load(text)
    except ModuleNotFoundError:
        raw = _simple_yaml_load(text)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid YAML: {exc}") from exc

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Config root must be a mapping/object")
    return raw


def load_config(path: Path) -> dict[str, Any]:
    config = _load_yaml(path)

    targets = config.get("targets")
    if targets is not None:
        if not isinstance(targets, list) or not all(isinstance(t, str) and t for t in targets):
            raise ValueError("'targets' must be a non-empty string list")

    scanners = config.get("scanners", {})
    if scanners is not None:
        if not isinstance(scanners, dict):
            raise ValueError("'scanners' must be a mapping")
        for key, value in scanners.items():
            if key not in SCANNER_KEYS:
                raise ValueError(f"Unsupported scanner toggle: {key}")
            if not isinstance(value, bool):
                raise ValueError(f"Scanner toggle '{key}' must be boolean")

    output = config.get("output", {})
    if output is not None:
        if not isinstance(output, dict):
            raise ValueError("'output' must be a mapping")
        out_format = output.get("format")
        if out_format is not None and out_format not in ALLOWED_FORMATS:
            raise ValueError("output.format must be one of: json, html, both")
        out_dir = output.get("out_dir")
        if out_dir is not None and not isinstance(out_dir, str):
            raise ValueError("output.out_dir must be a string path")

    timeouts = config.get("timeouts", {})
    if timeouts is not None:
        if not isinstance(timeouts, dict):
            raise ValueError("'timeouts' must be a mapping")
        for key in ("http", "tls"):
            node = timeouts.get(key)
            if node is None:
                continue
            if not isinstance(node, dict):
                raise ValueError(f"timeouts.{key} must be a mapping")
            timeout = node.get("timeout")
            if timeout is not None and (not isinstance(timeout, int) or timeout < 1):
                raise ValueError(f"timeouts.{key}.timeout must be a positive integer")

    return config


def resolve_runtime_config(
    target: str,
    raw_config: dict[str, Any],
    cli_out_dir: str | None,
    cli_format: str | None,
    cli_timeout: int | None,
    cli_nmap_args: str | None,
    cli_no_nmap: bool,
    default_nmap_args: str,
) -> dict[str, Any]:
    targets_from_config = raw_config.get("targets", [])
    effective_targets = [target]
    if targets_from_config:
        effective_targets = [str(t) for t in targets_from_config]
        if target not in effective_targets:
            effective_targets.insert(0, target)

    cfg_output = raw_config.get("output", {})
    cfg_timeouts = raw_config.get("timeouts", {})

    resolved_timeout = cli_timeout if cli_timeout is not None else 8
    resolved = {
        "targets": effective_targets,
        "out_dir": cli_out_dir or cfg_output.get("out_dir", "reports"),
        "format": cli_format or cfg_output.get("format", "both"),
        "timeout": resolved_timeout,
        "http_timeout": cfg_timeouts.get("http", {}).get("timeout", resolved_timeout),
        "tls_timeout": cfg_timeouts.get("tls", {}).get("timeout", resolved_timeout),
        "nmap_args": cli_nmap_args or default_nmap_args,
    }

    scanners = raw_config.get("scanners", {})
    resolved["enable_dns"] = scanners.get("dns", True)
    resolved["enable_http"] = scanners.get("http", True)
    resolved["enable_tls"] = scanners.get("tls", True)
    resolved["enable_nmap"] = scanners.get("nmap", True) and not cli_no_nmap

    return resolved
