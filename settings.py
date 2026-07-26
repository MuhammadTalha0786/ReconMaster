"""
settings.py
============
Persisted user settings for ReconMaster, backed by config.json in the
project root. Handles loading, saving, validating, and resolving the
active timeout for a given scan type based on the configured timeout
mode (default / custom / unlimited).

Kept as its own module (rather than folded into config.py) so the
built-in defaults in config.py stay immutable constants, while this
module owns the mutable, user-editable state and its I/O.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Optional

from config import CONFIG_FILE, DEFAULT_SETTINGS, SCAN_TIMEOUTS, VALID_REPORT_FORMATS

TIMEOUT_MODES = ("default", "custom", "unlimited")


@dataclass
class Settings:
    """User-configurable preferences, persisted to config.json."""
    timeout_mode: str = "default"
    custom_timeout_seconds: int = 300
    default_report_format: str = "txt"
    verbose_mode: bool = False
    color_output: bool = True

    def validate(self) -> None:
        """Clamp/normalize fields to safe values; never raises."""
        if self.timeout_mode not in TIMEOUT_MODES:
            self.timeout_mode = "default"
        if not isinstance(self.custom_timeout_seconds, int) or self.custom_timeout_seconds <= 0:
            self.custom_timeout_seconds = 300
        if self.default_report_format not in VALID_REPORT_FORMATS:
            self.default_report_format = "txt"
        self.verbose_mode = bool(self.verbose_mode)
        self.color_output = bool(self.color_output)


def load_settings() -> Settings:
    """
    Load settings from config.json, falling back to DEFAULT_SETTINGS for
    any missing or invalid keys. Creates config.json with defaults if it
    does not yet exist. Never raises — a corrupt config.json is treated
    as "use defaults" rather than crashing the program.
    """
    if not CONFIG_FILE.exists():
        settings = Settings(**DEFAULT_SETTINGS)
        save_settings(settings)
        return settings

    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return Settings(**DEFAULT_SETTINGS)

    merged = {**DEFAULT_SETTINGS, **{k: v for k, v in raw.items() if k in DEFAULT_SETTINGS}}
    settings = Settings(**merged)
    settings.validate()
    return settings


def save_settings(settings: Settings) -> bool:
    """Persist settings to config.json. Returns True on success."""
    settings.validate()
    try:
        CONFIG_FILE.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
        return True
    except OSError:
        return False


def resolve_timeout(scan_type: str, settings: Settings) -> Optional[int]:
    """
    Resolve the effective timeout (in seconds, or None for unlimited)
    for a given scan_type key (see config.SCAN_TIMEOUTS) under the
    currently active timeout mode.

    - "unlimited": always None, regardless of scan type.
    - "custom": the user's single custom_timeout_seconds value, applied
      to every scan type.
    - "default": the per-scan-type default from config.SCAN_TIMEOUTS
      (itself None for custom_command, meaning unlimited by default).
    """
    if settings.timeout_mode == "unlimited":
        return None
    if settings.timeout_mode == "custom":
        return settings.custom_timeout_seconds
    return SCAN_TIMEOUTS.get(scan_type, 300)
