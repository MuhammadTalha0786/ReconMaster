"""
utils.py
=========
Shared helper functions: target validation, input sanitization, timestamp
generation, and small formatting utilities used across ReconMaster.

Security note: user-controlled strings are validated here before ever
being placed into an argument list passed to subprocess. shell=True and
eval() are never used anywhere in this project.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from config import SAFE_ARG_PATTERN


def is_valid_ip(value: str) -> bool:
    """Return True if `value` is a syntactically valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    """
    Return True if `value` looks like a valid DNS hostname.

    This is a syntax check only (RFC 1123-ish); it does not guarantee the
    host resolves or is reachable.
    """
    if not value or len(value) > 253:
        return False
    if value.endswith("."):
        value = value[:-1]
    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )
    return bool(pattern.match(value))


def is_valid_cidr(value: str) -> bool:
    """Return True if `value` is a valid CIDR network, e.g. 192.168.1.0/24."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def validate_target(target: str) -> bool:
    """
    Validate a scan target: accepts an IP address, a CIDR range, or a
    hostname. Returns True only if at least one form matches.
    """
    target = target.strip()
    if not target:
        return False
    return is_valid_ip(target) or is_valid_cidr(target) or is_valid_hostname(target)


def resolve_hostname(target: str) -> Optional[str]:
    """Best-effort DNS resolution. Returns None if resolution fails."""
    try:
        return socket.gethostbyname(target)
    except socket.error:
        return None


def sanitize_custom_args(raw: str) -> Optional[str]:
    """
    Validate a user-supplied 'custom Nmap arguments' string against a
    strict allow-list of characters. Returns the stripped string if safe,
    otherwise None.

    This intentionally rejects shell metacharacters (;, |, &, `, $, etc.)
    so a custom argument string can never be used to break out of the
    argument list even though shell=True is never used.
    """
    raw = raw.strip()
    if not raw:
        return None
    if re.match(SAFE_ARG_PATTERN, raw):
        return raw
    return None


def timestamp_now() -> str:
    """Return the current time as YYYY_MM_DD_HHMMSS, used for filenames."""
    return datetime.now().strftime("%Y_%m_%d_%H%M%S")


def human_timestamp() -> str:
    """Return the current time in a human-readable form for reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def default_report_filename(target: str, extension: str) -> str:
    """
    Build a default report filename in the form:
    scan_<target>_<timestamp>.<extension>
    Target characters unsafe for filenames are stripped.
    """
    safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    return f"scan_{safe_target}_{timestamp_now()}.{extension}"


def sanitize_filename(name: str) -> str:
    """
    Sanitize a user-supplied filename so it can never escape the intended
    output directory (no path separators, no '..' traversal, no drive
    letters) and contains only filesystem-safe characters.

    Returns an empty string if nothing safe remains, so callers can fall
    back to an auto-generated timestamped name.
    """
    name = name.strip()
    # Strip any directory components the user may have supplied.
    name = Path(name).name
    # Remove characters that are unsafe or meaningless in a filename.
    name = re.sub(r"[^a-zA-Z0-9_.\-]", "_", name)
    # Collapse leading dots/underscores so it can't resolve to '.' or '..'.
    name = name.lstrip("._")
    return name


def validate_port_spec(spec: str) -> bool:
    """
    Validate a port list/range specification such as '22,80,443',
    '1-1000', or '22,80,1000-2000'. Returns True only if every token is
    a valid port number (1-65535) or a valid range of them.
    """
    spec = spec.strip()
    if not spec:
        return False
    if not re.match(r"^[0-9,\-]+$", spec):
        return False

    for token in spec.split(","):
        token = token.strip()
        if not token:
            return False
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2 or not all(p.isdigit() for p in parts):
                return False
            low, high = int(parts[0]), int(parts[1])
            if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
                return False
        else:
            if not token.isdigit() or not (1 <= int(token) <= 65535):
                return False
    return True


def ensure_directory(path: Path) -> None:
    """Create a directory (and parents) if it does not already exist."""
    path.mkdir(parents=True, exist_ok=True)


def format_duration(seconds: float) -> str:
    """Format an elapsed-seconds float as a compact human string."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes)}m {secs:.1f}s"


@dataclass
class MultiSelectionResult:
    """Outcome of parsing a multi-item selection string like '1,2,2,99'."""
    selected: List[int] = field(default_factory=list)   # valid, de-duplicated, in first-seen order
    invalid: List[str] = field(default_factory=list)    # tokens that weren't valid numbers in range
    duplicates: List[int] = field(default_factory=list)  # values seen more than once


def parse_multi_selection(raw: str, valid_range: range) -> MultiSelectionResult:
    """
    Parse a user-entered multi-selection string into validated integer
    choices. Accepts comma-separated ("1,2,3"), space-separated
    ("1 2 3"), or a mix ("1, 2 3"). Duplicates are kept once (in
    first-seen order) and reported separately; out-of-range or
    non-numeric tokens are reported as invalid rather than raising.

    Never raises on malformed input — always returns a result object.
    """
    result = MultiSelectionResult()
    if not raw or not raw.strip():
        return result

    # Split on commas and/or whitespace.
    tokens = [t for t in re.split(r"[,\s]+", raw.strip()) if t]
    seen = set()

    for token in tokens:
        if not token.isdigit():
            result.invalid.append(token)
            continue
        value = int(token)
        if value not in valid_range:
            result.invalid.append(token)
            continue
        if value in seen:
            result.duplicates.append(value)
            continue
        seen.add(value)
        result.selected.append(value)

    return result


def validate_timeout_value(raw: str) -> Optional[int]:
    """
    Validate a user-entered custom timeout in seconds. Returns the
    integer value if valid (a positive whole number), or None if the
    input is empty, non-numeric, zero, or negative. Callers treat None
    as "invalid — re-prompt", not as "unlimited" (unlimited is a
    separate, explicit menu choice).
    """
    raw = raw.strip()
    if not raw or not raw.isdigit():
        return None
    value = int(raw)
    if value <= 0:
        return None
    return value
