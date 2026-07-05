"""Data collectors for Linux agent inventory."""

from collectors.cron import collect_cron_jobs
from collectors.kernel import collect_kernel_info
from collectors.os_info import collect_os_info
from collectors.packages import collect_packages
from collectors.patches import collect_patches
from collectors.ports import collect_open_ports
from collectors.services import collect_running_services
from collectors.systemd import collect_systemd_services
from collectors.users import collect_users

COLLECTORS = {
    "os_info": collect_os_info,
    "packages": collect_packages,
    "running_services": collect_running_services,
    "open_ports": collect_open_ports,
    "users": collect_users,
    "cron_jobs": collect_cron_jobs,
    "systemd_services": collect_systemd_services,
    "kernel": collect_kernel_info,
    "patches": collect_patches,
}


def collect_all() -> dict:
    """Run all collectors and return aggregated inventory payload."""
    inventory = {}
    for name, collector in COLLECTORS.items():
        try:
            inventory[name] = collector()
        except Exception as exc:  # noqa: BLE001
            inventory[name] = {"error": str(exc)}
    return inventory
