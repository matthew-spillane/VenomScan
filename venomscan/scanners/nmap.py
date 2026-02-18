from __future__ import annotations

import shlex
import shutil
import subprocess
from typing import Any

DEFAULT_NMAP_ARGS = "-sT -Pn --top-ports 1000 -sV"


def parse_nmap_output(stdout: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "/tcp" not in line or "open" not in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        port = parts[0]
        state = parts[1]
        service = parts[2]
        version = " ".join(parts[3:]) if len(parts) > 3 else ""
        services.append(
            {
                "port": port,
                "state": state,
                "service": service,
                "version": version,
            }
        )
    return services


def run_nmap(target: str, timeout: int = 30, nmap_args: str | None = None) -> dict[str, Any]:
    if not shutil.which("nmap"):
        return {
            "available": False,
            "error": "nmap is not installed or not in PATH.",
            "command": None,
            "services": [],
            "stdout": "",
            "stderr": "",
        }

    effective_args = nmap_args or DEFAULT_NMAP_ARGS
    cmd = ["nmap", *shlex.split(effective_args), target]

    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "error": f"nmap timed out after {timeout} seconds",
            "command": " ".join(cmd),
            "services": [],
            "stdout": "",
            "stderr": "",
        }

    return {
        "available": True,
        "error": None if proc.returncode == 0 else f"nmap exited with code {proc.returncode}",
        "command": " ".join(cmd),
        "services": parse_nmap_output(proc.stdout),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
