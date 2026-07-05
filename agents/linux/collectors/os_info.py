"""Collect operating system information."""

import platform
import socket
import subprocess
from datetime import datetime, timezone


def _read_os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, _, value = line.partition("=")
                    data[key] = value.strip('"')
    except FileNotFoundError:
        pass
    return data


def collect_os_info() -> dict:
    os_release = _read_os_release()
    uptime_seconds = None
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
    except (FileNotFoundError, IndexError, ValueError):
        pass

    boot_time = None
    try:
        result = subprocess.run(
            ["uptime", "-s"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            boot_time = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "distribution": os_release.get("PRETTY_NAME", platform.platform()),
        "id": os_release.get("ID"),
        "version_id": os_release.get("VERSION_ID"),
        "uptime_seconds": uptime_seconds,
        "boot_time": boot_time,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
