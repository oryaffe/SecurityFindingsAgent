"""
Free ports 8000 (MCP) and 8080 (FastAPI app) before starting either server.

Cross-platform: uses PowerShell/Get-NetTCPConnection on Windows, lsof on
Linux/macOS (e.g. the EC2 deployment). Safe to run even if nothing is
listening on the ports -- it simply does nothing in that case.

Run standalone:
    python kill_ports.py

Or import and call free_port(port) from a launcher script before starting
mcp_server.py / uvicorn.
"""

from __future__ import annotations

import subprocess
import sys

PORTS = (8000, 8080)


def _pids_on_windows(port: int) -> set[str]:
    result = subprocess.run(
        [
            "powershell",
            "-Command",
            f"Get-NetTCPConnection -LocalPort {port} -State Listen "
            f"-ErrorAction SilentlyContinue | "
            f"Select-Object -ExpandProperty OwningProcess",
        ],
        capture_output=True,
        text=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _pids_on_unix(port: int) -> set[str]:
    result = subprocess.run(
        ["lsof", "-ti", f":{port}"],
        capture_output=True,
        text=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def free_port(port: int) -> None:
    """Kill whatever process is listening on *port*, if anything."""
    if sys.platform == "win32":
        pids = _pids_on_windows(port)
        kill_cmd = lambda pid: ["powershell", "-Command", f"Stop-Process -Id {pid} -Force"]
    else:
        pids = _pids_on_unix(port)
        kill_cmd = lambda pid: ["kill", "-9", pid]

    if not pids:
        return

    for pid in pids:
        subprocess.run(kill_cmd(pid))

    print(f"Port {port} was held by PID(s) {', '.join(sorted(pids))} -- killed.")


if __name__ == "__main__":
    for port in PORTS:
        free_port(port)
