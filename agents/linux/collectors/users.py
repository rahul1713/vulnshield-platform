"""Collect local user account information."""

import grp
import pwd
import subprocess


def _collect_logged_in() -> list[dict]:
    sessions = []
    try:
        result = subprocess.run(
            ["who"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                sessions.append(
                    {
                        "user": parts[0],
                        "terminal": parts[1],
                        "login_time": " ".join(parts[2:4]),
                        "host": parts[4] if len(parts) > 4 else None,
                    }
                )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return sessions


def collect_users() -> dict:
    users = []
    for entry in pwd.getpwall():
        try:
            groups = [g.gr_name for g in grp.getgrall() if entry.pw_name in g.gr_mem]
            if entry.pw_gid:
                try:
                    primary = grp.getgrgid(entry.pw_gid).gr_name
                    if primary not in groups:
                        groups.insert(0, primary)
                except KeyError:
                    pass
        except Exception:  # noqa: BLE001
            groups = []

        users.append(
            {
                "username": entry.pw_name,
                "uid": entry.pw_uid,
                "gid": entry.pw_gid,
                "home": entry.pw_dir,
                "shell": entry.pw_shell,
                "groups": groups,
            }
        )

    return {
        "count": len(users),
        "users": users,
        "active_sessions": _collect_logged_in(),
    }
