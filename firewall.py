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

import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Dict, List, Optional

from scanner import firewall_scan_args

# ---------------------------------------------------------------------------
# Technique metadata. Keys are stable identifiers used everywhere else in
# the project (menu selections, CLI flags, report sections, logging).
# ---------------------------------------------------------------------------
FIREWALL_TECHNIQUES: Dict[str, str] = {
    "ack": "ACK Scan (-sA) — maps firewall rule behavior (stateful vs stateless)",
    "window": "Window Scan (-sW) — TCP window-size based filtering analysis",
    "maimon": "Maimon Scan (-sM) — FIN/ACK probe filtering analysis",
    "fin": "FIN Scan (-sF) — FIN-flag-only filtering analysis",
    "null": "NULL Scan (-sN) — no TCP flags set filtering analysis",
    "xmas": "Xmas Scan (-sX) — FIN/PSH/URG flags filtering analysis",
    "idle": "Idle Scan (-sI) — zombie-host scan; requires an authorized lab zombie host",
    "bounce": "FTP Bounce Scan (-b) — requires an authorized, vulnerable FTP relay",
    "skip_ping": "No Ping (-Pn) — skip host discovery, assume host is up",
    "syn_ping": "TCP SYN Ping (-PS) — host discovery via TCP SYN probes",
    "ack_ping": "TCP ACK Ping (-PA) — host discovery via TCP ACK probes",
    "udp_ping": "UDP Ping (-PU) — host discovery via UDP probes",
    "icmp_ts_ping": "ICMP Timestamp Ping (-PP) — host discovery via ICMP timestamp request",
    "icmp_mask_ping": "ICMP Address Mask Ping (-PM) — host discovery via ICMP mask request",
    "fragment": "Fragment Packets (-f) — splits probes into 8-byte IP fragments",
    "double_fragment": "Double Fragment (-ff) — splits probes into smaller fragments still",
    "mtu": "Custom MTU (--mtu) — sets a custom fragment size (multiple of 8)",
    "data_length": "Append Random Data (--data-length) — appends random payload bytes to packets",
    "source_port": "Source Port (-g / --source-port) — sets a fixed source port",
    "source_route": "Source Routing (--ip-options) — sets IP options such as loose/strict source routing",
    "decoy": "Decoy Scan (-D) — hides the real source among decoy addresses",
    "spoof_mac": "Spoof MAC Address (--spoof-mac) — randomizes or sets a custom source MAC",
    "spoof_ip": "Spoof Source IP (-S) — sets a custom (usually invalid outside a lab) source IP",
    "spoof_iface": "Specific Interface (-e) — forces a network interface for the scan",
    "custom_ttl": "Custom TTL (--ttl) — sets a custom IP time-to-live",
    "bad_checksum": "Bad Checksums (--badsum) — sends packets with invalid TCP/UDP checksums",
    "paranoid_timing": "Paranoid Timing (-T0) — extremely slow, IDS-evasion-friendly timing",
    "sneaky_timing": "Sneaky Timing (-T1) — very slow timing, less conspicuous than defaults",
    "ip_protocol": "IP Protocol Scan (-sO) — determines which IP protocols the host supports",
}

# Techniques that select a *scan type* (mutually exclusive — Nmap accepts
# only one of -sA/-sW/-sM/-sF/-sN/-sX/-sO/-sI/-b per invocation).
SCAN_TYPE_TECHNIQUES = {
    "ack", "window", "maimon", "fin", "null", "xmas", "idle", "bounce", "ip_protocol",
}

# Techniques that are host-discovery / ping methods. More than one ping
# type can be combined in a single Nmap invocation, but a ping method
# cannot be combined with "skip_ping" (-Pn), which explicitly disables
# host discovery.
PING_TECHNIQUES = {
    "syn_ping", "ack_ping", "udp_ping", "icmp_ts_ping", "icmp_mask_ping",
}

# Techniques that are packet-crafting *modifiers* — these can be freely
# combined with each other and with one scan-type technique.
MODIFIER_TECHNIQUES = {
    "fragment", "double_fragment", "mtu", "data_length", "source_port",
    "source_route", "decoy", "spoof_mac", "spoof_ip", "spoof_iface",
    "custom_ttl", "bad_checksum", "paranoid_timing", "sneaky_timing",
}

# Techniques that need a user-supplied value to be meaningful.
TECHNIQUES_REQUIRING_VALUE = {
    "idle", "bounce", "mtu", "data_length", "source_port", "source_route",
    "decoy", "spoof_mac", "spoof_ip", "spoof_iface", "custom_ttl",
}

# Subset of the above with NO safe default in scanner.firewall_scan_args —
# without an actual value, the resulting Nmap command is incomplete
# (e.g. -sI with no zombie host, -S with no spoofed address), not merely
# "using a default". These MUST have an explicit, validated value; blank
# input is rejected and re-prompted rather than silently building a
# malformed command.
REQUIRES_EXPLICIT_VALUE = {"idle", "bounce", "spoof_ip", "spoof_iface"}

# The remaining value-taking techniques have a documented, safe default
# (see scanner.firewall_scan_args) — blank input is fine, but a value
# that IS supplied is still validated before use.
OPTIONAL_VALUE_TECHNIQUES = TECHNIQUES_REQUIRING_VALUE - REQUIRES_EXPLICIT_VALUE


def _looks_like_host(value: str) -> bool:
    """Loose syntax check for a plausible IP address or hostname."""
    if not value or any(c.isspace() for c in value):
        return False
    return bool(re.match(r"^[a-zA-Z0-9_.\-:]{1,253}$", value))


def validate_technique_value(key: str, value: Optional[str]) -> bool:
    """
    Validate a user-supplied value for a firewall technique that accepts
    one. Returns True if the value is acceptable (or if the technique
    doesn't take a value at all), False otherwise — callers use this to
    decide whether to accept input or re-prompt. Never raises.

    A blank/missing value is only acceptable for techniques in
    OPTIONAL_VALUE_TECHNIQUES (which fall back to a safe, documented
    default); for REQUIRES_EXPLICIT_VALUE techniques, blank is rejected
    outright since Nmap needs an actual value there.
    """
    if key not in TECHNIQUES_REQUIRING_VALUE:
        return True

    value = (value or "").strip()
    if not value:
        return key in OPTIONAL_VALUE_TECHNIQUES

    if key in ("idle", "bounce"):
        return _looks_like_host(value)
    if key == "spoof_ip":
        try:
            ip_address(value)
            return True
        except ValueError:
            return False
    if key == "spoof_iface":
        return bool(re.match(r"^[a-zA-Z0-9_.\-]{1,32}$", value))
    if key == "mtu":
        return value.isdigit() and int(value) > 0 and int(value) % 8 == 0
    if key == "data_length":
        return value.isdigit() and int(value) >= 0
    if key == "source_port":
        return value.isdigit() and 1 <= int(value) <= 65535
    if key == "custom_ttl":
        return value.isdigit() and 0 <= int(value) <= 255
    if key == "decoy":
        return bool(re.match(r"^[a-zA-Z0-9_.:,\-]+$", value))
    if key == "spoof_mac":
        return bool(re.match(r"^[a-zA-Z0-9_:.\-]{1,32}$", value))
    if key == "source_route":
        return bool(re.match(r"^[a-zA-Z0-9_.,\-]{1,64}$", value))

    return True  # unreachable given TECHNIQUES_REQUIRING_VALUE membership above


@dataclass
class FirewallTechnique:
    """Metadata for a single firewall/filtering-analysis technique."""
    key: str
    description: str
    args: List[str]


def describe_techniques() -> List[FirewallTechnique]:
    """Return all available firewall/filtering-analysis techniques."""
    return [
        FirewallTechnique(key=key, description=desc, args=[])
        for key, desc in FIREWALL_TECHNIQUES.items()
    ]


def build_firewall_args(technique_key: str, value: Optional[str] = None) -> List[str]:
    """Return the Nmap args for a single chosen firewall technique."""
    if technique_key not in FIREWALL_TECHNIQUES:
        raise ValueError(f"Unknown firewall technique: {technique_key}")
    if technique_key in REQUIRES_EXPLICIT_VALUE and not (value or "").strip():
        raise ValueError(
            f"Technique '{technique_key}' requires an explicit value (a zombie "
            "host, FTP relay, spoofed address, or interface name) — none was "
            "supplied. Refusing to build an incomplete Nmap command."
        )
    return firewall_scan_args(technique_key, value)


@dataclass
class FirewallCombinationPlan:
    """
    Result of validating a set of selected firewall techniques for
    combination into Nmap invocation(s).

    `groups` is a list of technique-key lists; each inner list is safe to
    combine into a single Nmap command. Multiple groups mean multiple
    separate Nmap invocations are required (e.g. two conflicting scan
    types were selected together).
    """
    groups: List[List[str]]
    notes: List[str]


def validate_firewall_combination(selected_keys: List[str]) -> FirewallCombinationPlan:
    """
    Decide how a set of selected firewall technique keys can safely be
    combined into one or more Nmap invocations.

    Rules:
    - At most one "scan type" technique (ack/window/maimon/fin/null/xmas/
      idle/bounce/ip_protocol) can appear in a single Nmap command —
      Nmap does not support combining multiple scan types in one run.
      Extra scan-type selections become their own separate group.
    - "skip_ping" (-Pn) cannot be combined with any ping-method technique
      (-PS/-PA/-PU/-PP/-PM) — they are contradictory (one disables host
      discovery, the others perform it). skip_ping is split into its own
      group if both are selected.
    - Ping-method techniques may be combined freely with each other and
      with a scan-type technique or modifiers.
    - Modifier techniques (fragmentation, MTU, spoofing, decoys, timing,
      etc.) may be combined with each other and with one scan-type group.

    Unknown technique keys are ignored (should be filtered out by the
    caller's own selection validation beforehand).
    """
    selected_keys = [k for k in selected_keys if k in FIREWALL_TECHNIQUES]
    notes: List[str] = []

    scan_types = [k for k in selected_keys if k in SCAN_TYPE_TECHNIQUES]
    pings = [k for k in selected_keys if k in PING_TECHNIQUES]
    modifiers = [k for k in selected_keys if k in MODIFIER_TECHNIQUES]
    has_skip_ping = "skip_ping" in selected_keys

    groups: List[List[str]] = []

    if len(scan_types) > 1:
        notes.append(
            "These scan-type techniques cannot be combined into one Nmap "
            f"command ({', '.join(scan_types)}). ReconMaster will execute "
            "them as separate authorized analysis tasks."
        )

    if has_skip_ping and pings:
        notes.append(
            "No Ping (-Pn) cannot be combined with ping-discovery methods "
            f"({', '.join(pings)}) — they are contradictory. ReconMaster "
            "will run No Ping as a separate task."
        )

    # Build the primary combined group: first scan type (if any) + all
    # pings (unless skip_ping conflicts) + all modifiers.
    primary: List[str] = []
    if scan_types:
        primary.append(scan_types[0])
    if not (has_skip_ping and pings):
        primary.extend(pings)
        if has_skip_ping:
            primary.append("skip_ping")
    else:
        # Conflict: keep pings in primary, skip_ping goes to its own group.
        primary.extend(pings)
    primary.extend(modifiers)

    if primary:
        groups.append(primary)

    # Any additional scan types beyond the first each get their own group.
    for extra_scan_type in scan_types[1:]:
        groups.append([extra_scan_type])

    # skip_ping gets its own group if it conflicted with selected pings.
    if has_skip_ping and pings:
        groups.append(["skip_ping"])

    if not groups:
        groups = [[]]

    return FirewallCombinationPlan(groups=groups, notes=notes)


def build_args_for_group(group: List[str], values: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Build a combined Nmap argument list for a group of compatible
    technique keys (as produced by validate_firewall_combination).
    `values` maps technique key -> user-supplied value, for techniques
    in TECHNIQUES_REQUIRING_VALUE.
    """
    values = values or {}
    args: List[str] = []
    for key in group:
        args.extend(build_firewall_args(key, values.get(key)))
    return args
