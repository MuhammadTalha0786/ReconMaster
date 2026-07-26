"""
config.py
==========
Central configuration for ReconMaster.

Holds paths, version info, default per-scan-type timeouts, and Nmap
option maps used across the project. User-adjustable preferences
(timeout mode, report format, verbose mode, color output) live in
config.json and are managed by settings.py — this module only defines
the built-in defaults those preferences are validated/initialized
against.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Project metadata
# ---------------------------------------------------------------------------
APP_NAME = "ReconMaster"
APP_SUBTITLE = "Advanced Network Reconnaissance Framework"
APP_VERSION = "1.0.0"
AUTHOR = "Talha"

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
OUTPUT_DIR = BASE_DIR / "output"
SAMPLE_REPORTS_DIR = BASE_DIR / "sample_reports"
CONFIG_FILE = BASE_DIR / "config.json"

for _dir in (REPORTS_DIR, LOGS_DIR, OUTPUT_DIR):
    _dir.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Nmap / socket defaults
# ---------------------------------------------------------------------------
NMAP_BINARY = "nmap"          # Must be resolvable on PATH
BANNER_GRAB_TIMEOUT = 3        # seconds, per-port socket timeout
BANNER_GRAB_THREADS = 20       # concurrent banner-grab workers

# Common ports used for quick banner grabbing when the user hasn't
# supplied a specific port list.
COMMON_BANNER_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

# ---------------------------------------------------------------------------
# Per-scan-type default timeouts (seconds). A fixed 300s timeout for
# every scan type is unrealistic — OS detection, firewall assessment,
# and NSE script scans routinely need much longer than a quick host
# discovery sweep. These are the "Default Timeout" values used when the
# active timeout mode is 'default'. `None` means unlimited.
# ---------------------------------------------------------------------------
SCAN_TIMEOUTS = {
    "host_discovery": 60,
    "port_scan": 180,
    "service_detection": 300,
    "banner_grab": 120,
    "os_detection": 600,
    "aggressive_scan": 1200,
    "firewall_assessment": 1800,
    "nse_scan": 1800,
    "custom_command": None,   # unlimited by default
}

# ---------------------------------------------------------------------------
# Report output formats
# ---------------------------------------------------------------------------
REPORT_FORMATS = {
    "1": "terminal",
    "2": "txt",
    "3": "xml",
    "4": "json",
    "5": "html",
    "6": "pdf",
    "7": "all",
}
VALID_REPORT_FORMATS = ["terminal", "txt", "xml", "json", "html", "pdf", "all"]

# ---------------------------------------------------------------------------
# NSE script categories -> representative Nmap script arguments
# ---------------------------------------------------------------------------
NSE_CATEGORIES = {
    "default": "default",
    "safe": "safe",
    "discovery": "discovery",
    "http": "http-*",
    "ftp": "ftp-*",
    "dns": "dns-*",
    "ssh": "ssh-*",
    "ssl": "ssl-*",
    "smb": "smb-*",
    "smtp": "smtp-*",
    "snmp": "snmp-*",
    "auth": "auth",
    "broadcast": "broadcast",
    "vuln": "vuln",
    "malware": "malware",
}

# Allowed characters for a sanitized custom Nmap argument string.
# Deliberately excludes shell metacharacters since we never use shell=True.
SAFE_ARG_PATTERN = r"^[a-zA-Z0-9\-\./,: _]+$"

# ---------------------------------------------------------------------------
# Default persisted settings (written to config.json on first run).
# See settings.py for the loader/saver and the Settings dataclass.
# ---------------------------------------------------------------------------
DEFAULT_SETTINGS = {
    "timeout_mode": "default",      # "default" | "custom" | "unlimited"
    "custom_timeout_seconds": 300,  # used only when timeout_mode == "custom"
    "default_report_format": "txt",
    "verbose_mode": False,
    "color_output": True,
}
