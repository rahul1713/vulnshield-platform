"""Collect kernel version and module information."""

import platform
import subprocess


def collect_kernel_info() -> dict:
    info = {
        "kernel_version": platform.release(),
        "kernel_full": platform.uname().version,
        "architecture": platform.machine(),
    }

    try:
        with open("/proc/version") as f:
            info["proc_version"] = f.read().strip()
    except FileNotFoundError:
        pass

    modules = []
    try:
        result = subprocess.run(
            ["lsmod"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines()[1:]:
                parts = line.split()
                if parts:
                    modules.append({"name": parts[0], "size": parts[1] if len(parts) > 1 else None})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    info["loaded_modules_count"] = len(modules)
    info["loaded_modules"] = modules[:200]
    info["modules_truncated"] = len(modules) > 200
    return info
