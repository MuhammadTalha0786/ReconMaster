"""
banner.py
==========
Lightweight, safe banner grabbing over TCP sockets. Connects to a port,
optionally sends a minimal protocol-appropriate probe, and reads back
whatever the service announces. Fails gracefully (timeouts, closed
ports, refused connections) without raising to the caller.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

from config import BANNER_GRAB_THREADS, BANNER_GRAB_TIMEOUT, COMMON_BANNER_PORTS

# Minimal probes for protocols that don't send a banner unprompted.
_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"",  # TLS handshake not implemented here; left blank intentionally
}


@dataclass
class BannerResult:
    host: str
    port: int
    banner: Optional[str]
    reachable: bool


def grab_banner(host: str, port: int, timeout: float = BANNER_GRAB_TIMEOUT) -> BannerResult:
    """Attempt to grab a single banner from host:port. Never raises."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            probe = _PROBES.get(port)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    pass

            try:
                data = sock.recv(1024)
                banner = data.decode(errors="replace").strip()
            except socket.timeout:
                banner = ""

            return BannerResult(host=host, port=port, banner=banner or None, reachable=True)

    except (socket.timeout, ConnectionRefusedError, OSError):
        return BannerResult(host=host, port=port, banner=None, reachable=False)


def grab_banners(
    host: str, ports: Optional[List[int]] = None, timeout: float = BANNER_GRAB_TIMEOUT
) -> List[BannerResult]:
    """
    Grab banners across multiple ports concurrently using a thread pool.
    Defaults to a small, common-service port list if none is supplied.
    """
    ports = ports or COMMON_BANNER_PORTS
    results: List[BannerResult] = []

    with ThreadPoolExecutor(max_workers=BANNER_GRAB_THREADS) as executor:
        futures = {
            executor.submit(grab_banner, host, port, timeout): port for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.port)
    return results
