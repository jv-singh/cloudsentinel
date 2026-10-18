"""System health checks: CPU, memory, disk and service status."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import psutil

THRESHOLDS: dict[str, float] = {"cpu": 85.0, "memory": 90.0, "disk": 90.0}
DISK_PATH = Path.cwd().anchor or "/"  # "C:\\" on Windows, "/" on Linux


def collect_metrics() -> dict[str, float]:
    return {
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage(DISK_PATH).percent,
    }


def evaluate(metrics: dict[str, float],
             thresholds: dict[str, float] = THRESHOLDS) -> list[dict]:
    return [
        {
            "metric": name,
            "value": value,
            "threshold": thresholds[name],
            "severity": "CRITICAL" if value >= 95 else "HIGH",
        }
        for name, value in metrics.items()
        if value >= thresholds[name]
    ]


def service_active(name: str) -> bool | None:
    """True/False on systemd hosts; None where systemctl is unavailable."""
    if shutil.which("systemctl") is None:
        return None
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", name], check=False
    )
    return result.returncode == 0


if __name__ == "__main__":
    current = collect_metrics()
    report = {
        "metrics": current,
        "alerts": evaluate(current),
        "ssh_active": service_active("ssh"),
    }
    print(json.dumps(report, indent=2))