"""Simple TCP port check. Run it on your own device or your own public IP."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .checks import HIGH, INFO, MEDIUM, PASS, Finding

# port: (name, severity if reachable)
PORTS = {
    21: ("FTP", HIGH),
    22: ("SSH", MEDIUM),
    23: ("Telnet", HIGH),
    80: ("HTTP web", MEDIUM),
    443: ("HTTPS web", INFO),
    554: ("RTSP video", MEDIUM),
    8000: ("Hikvision SDK / iVMS", MEDIUM),
    8080: ("HTTP alt", MEDIUM),
    8200: ("Hikvision SDK alt", MEDIUM),
    8443: ("HTTPS alt", INFO),
}


def is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan(host: str, ports=None, timeout: float = 1.5, public: bool = False):
    ports = ports or PORTS
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = dict(zip(ports, pool.map(lambda p: is_open(host, p, timeout), ports)))
    out = []
    for port, opened in results.items():
        if not opened:
            continue
        name, sev = ports[port]
        if public:
            # Anything a camera exposes to the internet is a serious problem.
            out.append(Finding(f"port-{port}", HIGH, f"Port {port} ({name}) is open to the internet",
                               "Someone set up port forwarding or UPnP opened it.",
                               "Remove the port forward on your router and turn off UPnP."))
        else:
            out.append(Finding(f"port-{port}", sev, f"Port {port} ({name}) is open"))
    if not out:
        out.append(Finding("ports", PASS, f"No common camera ports open on {host}"))
    return out
