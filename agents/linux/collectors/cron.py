"""Collect cron job definitions."""

import glob
import subprocess


def _parse_crontab(content: str, source: str) -> list[dict]:
    jobs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        jobs.append({"source": source, "schedule": line})
    return jobs


def collect_cron_jobs() -> dict:
    jobs: list[dict] = []

    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            jobs.extend(_parse_crontab(result.stdout, "user_crontab"))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    for path in glob.glob("/etc/cron.d/*") + ["/etc/crontab"]:
        try:
            with open(path) as f:
                jobs.extend(_parse_crontab(f.read(), path))
        except OSError:
            continue

    for path in glob.glob("/etc/cron.daily/*"):
        jobs.append({"source": path, "schedule": "@daily", "script": path})

    return {"count": len(jobs), "jobs": jobs}
