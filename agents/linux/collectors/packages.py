"""Collect installed package inventory."""

import shutil
import subprocess


def _collect_dpkg() -> list[dict]:
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    packages = []
    if result.returncode != 0:
        return packages
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            packages.append(
                {
                    "name": parts[0],
                    "version": parts[1],
                    "vendor": parts[2] if len(parts) > 2 else None,
                    "package_manager": "dpkg",
                }
            )
    return packages


def _collect_rpm() -> list[dict]:
    result = subprocess.run(
        ["rpm", "-qa", "--queryformat", r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    packages = []
    if result.returncode != 0:
        return packages
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            packages.append(
                {
                    "name": parts[0],
                    "version": parts[1],
                    "vendor": parts[2] if len(parts) > 2 else None,
                    "package_manager": "rpm",
                }
            )
    return packages


def _collect_apk() -> list[dict]:
    result = subprocess.run(
        ["apk", "info", "-v"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    packages = []
    if result.returncode != 0:
        return packages
    for line in result.stdout.strip().splitlines():
        if "-" in line:
            name, _, version = line.rpartition("-")
            packages.append(
                {"name": name, "version": version, "package_manager": "apk"}
            )
    return packages


def collect_packages() -> dict:
    manager = None
    packages: list[dict] = []

    if shutil.which("dpkg-query"):
        manager = "dpkg"
        packages = _collect_dpkg()
    elif shutil.which("rpm"):
        manager = "rpm"
        packages = _collect_rpm()
    elif shutil.which("apk"):
        manager = "apk"
        packages = _collect_apk()

    return {
        "package_manager": manager,
        "count": len(packages),
        "packages": packages[:5000],
        "truncated": len(packages) > 5000,
    }
