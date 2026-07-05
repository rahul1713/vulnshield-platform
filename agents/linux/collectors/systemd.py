"""Collect systemd unit status."""

import json
import shutil
import subprocess


def collect_systemd_services() -> dict:
    if not shutil.which("systemctl"):
        return {"available": False, "services": []}

    result = subprocess.run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--plain",
            "--output=json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    services = []
    if result.returncode == 0 and result.stdout.strip():
        try:
            units = json.loads(result.stdout)
            for unit in units:
                services.append(
                    {
                        "name": unit.get("unit"),
                        "load_state": unit.get("load"),
                        "active_state": unit.get("active"),
                        "sub_state": unit.get("sub"),
                        "description": unit.get("description"),
                    }
                )
        except json.JSONDecodeError:
            pass

    enabled_result = subprocess.run(
        ["systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    enabled_map: dict[str, str] = {}
    if enabled_result.returncode == 0:
        for line in enabled_result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                enabled_map[parts[0]] = parts[1]

    for svc in services:
        svc["enabled"] = enabled_map.get(svc["name"], "unknown")

    return {"available": True, "count": len(services), "services": services}
