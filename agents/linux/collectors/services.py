"""Collect running process/service information."""

import psutil


def collect_running_services() -> dict:
    services = []
    for proc in psutil.process_iter(
        ["pid", "name", "username", "status", "cmdline", "create_time"]
    ):
        try:
            info = proc.info
            services.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "user": info["username"],
                    "status": info["status"],
                    "cmdline": " ".join(info["cmdline"] or [])[:500],
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return {"count": len(services), "processes": services[:1000], "truncated": len(services) > 1000}
