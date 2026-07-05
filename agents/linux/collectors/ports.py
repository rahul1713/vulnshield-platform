"""Collect open network ports."""

import psutil


def collect_open_ports() -> dict:
    ports = []
    seen = set()

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN:
            continue
        key = (conn.laddr.port, "tcp" if conn.type.name == "SOCK_STREAM" else "udp")
        if key in seen:
            continue
        seen.add(key)
        ports.append(
            {
                "port": conn.laddr.port,
                "protocol": key[1],
                "address": conn.laddr.ip,
                "pid": conn.pid,
                "state": conn.status,
            }
        )

    ports.sort(key=lambda p: p["port"])
    return {"count": len(ports), "ports": ports}
