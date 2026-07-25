"""
nse.py
=======
Helper layer for Nmap Scripting Engine (NSE) category selection. Maps
friendly category names to the script expressions passed to Nmap via
--script, and validates individual script names the user types in.
"""

from __future__ import annotations

import re
from typing import List, Optional

from config import NSE_CATEGORIES

_SCRIPT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9\-_,\*]+$")


def list_categories() -> List[str]:
    """Return the available NSE category keys in display order."""
    return list(NSE_CATEGORIES.keys())


def category_to_script_expr(category_key: str) -> str:
    """Translate a category key (e.g. 'http') to its --script expression."""
    return NSE_CATEGORIES.get(category_key, "default")


def validate_script_name(name: str) -> Optional[str]:
    """
    Validate a user-typed NSE script name or comma-separated list
    (e.g. 'http-title,http-headers' or 'smb-os-discovery'). Returns the
    trimmed string if it passes a safe allow-list check, else None.
    """
    name = name.strip()
    if not name:
        return None
    if _SCRIPT_NAME_PATTERN.match(name):
        return name
    return None
