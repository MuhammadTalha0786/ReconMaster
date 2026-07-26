"""
scanner.py
===========
Core scanning engine. Wraps standard Nmap functionality through
subprocess (never shell=True). All scan "modes" build an argument list
and hand it to `run_nmap`, which executes Nmap, captures output, and
returns a structured ScanResult.

This module intentionally only exposes standard, documented Nmap
options. No exploitation, payload, or credential-harvesting logic is
implemented anywhere in this file.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

from config import NMAP_BINARY, NSE_CATEGORIES
from logger import get_logger, log_error, log_scan_end, log_scan_start, log_warning

logger = get_logger()


class NmapNotFoundError(Exception):
    """Raised when the nmap binary cannot be located on PATH."""


class ScanTimeoutError(Exception):
    """Raised when a scan exceeds the configured timeout."""


@dataclass
class ScanResult:
    """Structured result of a single Nmap invocation."""
    target: str
    command: List[str]
    raw_output: str = ""
    xml_output: str = ""
    success: bool = False
    error_message: str = ""
    duration_seconds: float = 0.0
    started_at: str = ""
    ended_at: str = ""
    open_ports: List[dict] = field(default_factory=list)


def check_nmap_available() -> bool:
    """Return True if the nmap binary is resolvable on PATH."""
    return shutil.which(NMAP_BINARY) is not None


def _build_base_args(target: str) -> List[str]:
    """Return the base [nmap] argument list for a given target."""
    if not check_nmap_available():
        raise NmapNotFoundError(
            "Nmap was not found on PATH. Install Nmap and ensure it is "
            "accessible from the command line."
        )
    return [NMAP_BINARY]


def run_nmap_with_xml(
    target: str, extra_args: List[str], timeout: Optional[int] = None
) -> ScanResult:
    """
    Run nmap once, requesting both normal output and XML output written
    to a single pass using '-oX -' combined with normal output via
    '-oN -' is not supported simultaneously to stdout, so this helper
    runs Nmap once with '-oX -' and derives the human-readable summary
    from the XML rather than invoking Nmap twice.

    `timeout` is the ReconMaster *application* timeout in seconds — the
    maximum time ReconMaster will wait for the Nmap subprocess before
    giving up and terminating it. Pass None for no application timeout
    (ReconMaster waits indefinitely; Nmap's own internal timing options,
    if any were passed in extra_args, still apply on Nmap's side).

    This is distinct from Nmap's own scan timing (-T0..-T5, --host-
    timeout, etc.) which controls how Nmap paces its own probes. If the
    application timeout is reached, subprocess.run() has already
    terminated the child process for us — we report this explicitly as
    an application-timeout condition, not as "the Nmap scan failed",
    since Nmap itself never got the chance to fail or succeed.
    """
    args = _build_base_args(target)
    args.extend(extra_args)
    args.extend(["-oX", "-"])
    args.append(target)

    result = ScanResult(target=target, command=args)
    start_time = time.time()
    result.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
    log_scan_start(logger, target, args)

    try:
        completed = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, shell=False, check=False,
        )
        result.xml_output = completed.stdout
        result.raw_output = completed.stdout
        result.success = completed.returncode == 0
        if not result.success:
            result.error_message = completed.stderr.strip()

    except subprocess.TimeoutExpired:
        # subprocess.run() already killed the child process for us on
        # TimeoutExpired. This is a ReconMaster *application* timeout,
        # not an Nmap failure — Nmap never got to finish or report a
        # result, so we must not describe this as "the scan failed".
        timeout_label = f"{timeout} seconds" if timeout else "the configured limit"
        result.error_message = (
            f"Application timeout reached after {timeout_label} — Nmap was "
            "still running and was terminated. This does not mean the scan "
            "failed; it means ReconMaster stopped waiting. Increase the "
            "timeout (Settings, or choose 'Custom'/'No application timeout') "
            "if this scan legitimately needs more time."
        )
        log_error(logger, result.error_message)
        raise ScanTimeoutError(result.error_message)

    except FileNotFoundError:
        result.error_message = "Nmap executable not found."
        log_error(logger, result.error_message)
        raise NmapNotFoundError(result.error_message)

    except PermissionError:
        result.error_message = (
            "Permission denied. Some scan types (e.g. SYN scan, OS "
            "detection, firewall/packet-crafting techniques) require "
            "elevated privileges (root/Administrator)."
        )
        log_error(logger, result.error_message)

    except KeyboardInterrupt:
        result.error_message = "Scan interrupted by user."
        log_warning(logger, result.error_message)
        raise

    except OSError as exc:
        # Covers host-unreachable / network-down conditions surfaced by
        # the OS layer rather than by Nmap's own return code.
        result.error_message = f"Network error while scanning {target}: {exc}"
        log_error(logger, result.error_message)

    except Exception as exc:  # noqa: BLE001 - last-resort safety net, surfaced to caller/UI
        result.error_message = f"Unexpected error while running Nmap: {exc}"
        log_error(logger, result.error_message)

    finally:
        result.duration_seconds = time.time() - start_time
        result.ended_at = time.strftime("%Y-%m-%d %H:%M:%S")
        log_scan_end(logger, target, result.duration_seconds)

    return result


# ---------------------------------------------------------------------------
# Scan mode builders — each returns the Nmap CLI arguments for that mode.
# Actual execution is left to the caller (menu.py / cli.py) via run_nmap*.
# ---------------------------------------------------------------------------

def host_discovery_args() -> List[str]:
    return ["-sn"]


def port_scan_args(mode: str, ports: Optional[str] = None) -> List[str]:
    """
    mode: one of 'syn', 'connect', 'udp', 'full', 'fast', 'top100',
          'top1000', 'ports', 'range'
    """
    mapping = {
        "syn": ["-sS"],
        "connect": ["-sT"],
        "udp": ["-sU"],
        "full": ["-p-"],
        "fast": ["-F"],
        "top100": ["--top-ports", "100"],
        "top1000": ["--top-ports", "1000"],
    }
    if mode in mapping:
        return mapping[mode]
    if mode in ("ports", "range") and ports:
        return ["-p", ports]
    return ["-F"]  # sensible default fallback


def service_detection_args(mode: str) -> List[str]:
    mapping = {
        "version": ["-sV"],
        "version_default_scripts": ["-sV", "-sC"],
        "enumeration": ["-sV", "--version-intensity", "5"],
    }
    return mapping.get(mode, ["-sV"])


def os_detection_args(include_traceroute: bool = False) -> List[str]:
    args = ["-O"]
    if include_traceroute:
        args.append("--traceroute")
    return args


def nse_script_args(category_key: str, custom_script: Optional[str] = None) -> List[str]:
    if custom_script:
        return ["--script", custom_script]
    script_expr = NSE_CATEGORIES.get(category_key, "default")
    return ["--script", script_expr]


def nse_multi_script_args(category_keys: List[str]) -> List[str]:
    """
    Build a single --script argument combining multiple NSE categories
    using Nmap's supported comma-separated syntax, e.g.
    --script default,safe,vuln — this runs one Nmap process instead of
    one per selected category.
    """
    if not category_keys:
        return ["--script", "default"]
    exprs = [NSE_CATEGORIES.get(key, key) for key in category_keys]
    return ["--script", ",".join(exprs)]


def vuln_scan_args() -> List[str]:
    return ["--script", "vuln"]


def firewall_scan_args(technique: str, value: Optional[str] = None) -> List[str]:
    """
    Standard Nmap firewall / filtering-analysis techniques. These are
    legitimate, well-documented Nmap options used for network assessment
    and firewall rule-set analysis — NOT guaranteed bypass methods.

    `value` is required (or has a documented safe default) for
    techniques that take a parameter (idle zombie host, FTP relay,
    MTU size, decoys, spoofed addresses, interface name, TTL, etc.).
    """
    mapping = {
        # --- mutually exclusive scan types ---
        "ack": ["-sA"],
        "window": ["-sW"],
        "maimon": ["-sM"],
        "fin": ["-sF"],
        "null": ["-sN"],
        "xmas": ["-sX"],
        "idle": ["-sI", value] if value else ["-sI"],
        "bounce": ["-b", value] if value else ["-b"],
        "ip_protocol": ["-sO"],
        # --- ping / host-discovery methods (combinable) ---
        "skip_ping": ["-Pn"],
        "syn_ping": [f"-PS{value}"] if value else ["-PS"],
        "ack_ping": [f"-PA{value}"] if value else ["-PA"],
        "udp_ping": [f"-PU{value}"] if value else ["-PU"],
        "icmp_ts_ping": ["-PP"],
        "icmp_mask_ping": ["-PM"],
        # --- packet-crafting modifiers (combinable) ---
        "fragment": ["-f"],
        "double_fragment": ["-ff"],
        "mtu": ["--mtu", value] if value else ["--mtu", "24"],
        "data_length": ["--data-length", value] if value else ["--data-length", "25"],
        "source_port": ["-g", value] if value else ["-g", "53"],
        "source_route": ["--ip-options", value] if value else ["--ip-options", "L"],
        "decoy": ["-D", value] if value else ["-D", "RND:5"],
        "spoof_mac": ["--spoof-mac", value] if value else ["--spoof-mac", "0"],
        "spoof_ip": ["-S", value] if value else [],
        "spoof_iface": ["-e", value] if value else [],
        "custom_ttl": ["--ttl", value] if value else ["--ttl", "64"],
        "bad_checksum": ["--badsum"],
        "paranoid_timing": ["-T0"],
        "sneaky_timing": ["-T1"],
    }
    return mapping.get(technique, [])


def aggressive_scan_args() -> List[str]:
    return ["-A"]


def custom_command_args(sanitized_args: str) -> List[str]:
    """Split an already-sanitized argument string into a list."""
    return sanitized_args.split()
