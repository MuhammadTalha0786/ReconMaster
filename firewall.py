"""
firewall.py
============
Thin wrapper around scanner.firewall_scan_args() that adds descriptive
metadata for the menu/report layer. These are standard, publicly
documented Nmap scan techniques used for firewall rule-set analysis and
network assessment during AUTHORIZED testing.

IMPORTANT: None of these techniques guarantee bypassing a firewall or
IDS/IPS. They are diagnostic tools that reveal how a target's filtering
responds to different packet types — nothing more. Results should
always be interpreted by a qualified analyst.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from scanner import firewall_scan_args

FIREWALL_TECHNIQUES: Dict[str, str] = {
    "ack": "ACK Scan — maps firewall rule sets (stateful vs stateless filtering)",
    "window": "Window Scan — variant of ACK scan using TCP window size quirks",
    "fin": "FIN Scan — sends FIN flag only; some stateless filters ignore it",
    "null": "NULL Scan — sends a packet with no flags set",
    "xmas": "Xmas Scan — sends FIN, PSH, and URG flags together",
    "idle": "Idle Scan — uses a zombie host to scan anonymously (requires --value)",
    "fragment": "Fragment Packets — splits probes into smaller IP fragments",
    "mtu": "Custom MTU — sets a custom fragment size (--value, multiple of 8)",
    "spoof_mac": "Spoof MAC Address — randomizes or sets a custom source MAC",
    "source_port": "Source Port — sets a fixed source port (e.g. 53, 88) to test filtering",
}


@dataclass
class FirewallTechnique:
    key: str
    description: str
    args: List[str]


def describe_techniques() -> List[FirewallTechnique]:
    """Return all available firewall/evasion-analysis techniques with args."""
    techniques = []
    for key, desc in FIREWALL_TECHNIQUES.items():
        techniques.append(FirewallTechnique(key=key, description=desc, args=[]))
    return techniques


def build_firewall_args(technique_key: str, value: Optional[str] = None) -> List[str]:
    """Return the Nmap args for a chosen firewall technique."""
    if technique_key not in FIREWALL_TECHNIQUES:
        raise ValueError(f"Unknown firewall technique: {technique_key}")
    return firewall_scan_args(technique_key, value)
