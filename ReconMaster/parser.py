"""
parser.py
==========
Small helper that extracts structured port/service/OS data out of Nmap's
plain-text output so it can be embedded into reports. This is a
best-effort regex-based parser intended for readability in reports, not
a full replacement for Nmap's own XML (which is more authoritative and
also produced by run_nmap_with_xml in scanner.py).
"""

from __future__ import annotations

import re
from typing import Dict, List

_PORT_LINE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$", re.MULTILINE
)
_OS_LINE = re.compile(r"OS details:\s*(.+)")
_OS_GUESS_LINE = re.compile(r"Running:\s*(.+)")


def parse_open_ports(nmap_output: str) -> List[Dict]:
    """Extract a list of {port, protocol, state, service, version} dicts."""
    ports = []
    for match in _PORT_LINE.finditer(nmap_output):
        port, proto, state, service, extra = match.groups()
        if state.lower() != "open":
            continue
        ports.append(
            {
                "port": int(port),
                "protocol": proto,
                "state": state,
                "service": service + (f" {extra}" if extra else ""),
            }
        )
    return ports


def parse_os_guess(nmap_output: str) -> str:
    """Extract an OS detection summary line, if present."""
    match = _OS_LINE.search(nmap_output)
    if match:
        return match.group(1).strip()
    match = _OS_GUESS_LINE.search(nmap_output)
    if match:
        return match.group(1).strip()
    return ""
