"""Collect installed security patches and pending updates."""

import shutil
import subprocess


def _collect_apt_patches() -> dict:
    pending = []
    installed = []

    result = subprocess.run(
        ["apt list", "--upgradable"],
        shell=True,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode == 0:
        for line in result.stdout.strip().splitlines()[1:]:
            if "/" in line:
                name = line.split("/")[0]
                pending.append(name)

    history_result = subprocess.run(
        ["grep", "-h", "Upgrade:", "/var/log/apt/history.log"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if history_result.returncode == 0:
        for line in history_result.stdout.strip().splitlines()[-50:]:
            installed.append(line.replace("Upgrade:", "").strip())

    return {
        "package_manager": "apt",
        "pending_updates": pending[:100],
        "pending_count": len(pending),
        "recent_upgrades": installed,
    }


def _collect_yum_patches() -> dict:
    result = subprocess.run(
        ["yum", "updateinfo", "list", "security", "--quiet"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    advisories = []
    if result.returncode == 0:
        for line in result.stdout.strip().splitlines():
            if line.strip():
                advisories.append(line.strip())

    return {
        "package_manager": "yum",
        "security_advisories": advisories[:100],
        "advisory_count": len(advisories),
    }


def collect_patches() -> dict:
    if shutil.which("apt"):
        return _collect_apt_patches()
    if shutil.which("yum") or shutil.which("dnf"):
        return _collect_yum_patches()
    return {"package_manager": None, "message": "No supported package manager found"}
