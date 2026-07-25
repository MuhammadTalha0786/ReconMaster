"""
config.py
==========
Central configuration for ReconMaster.

Holds paths, version info, default timeouts, and Nmap option maps used
across the project. Keeping these in one place avoids magic strings
scattered through the codebase.
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

for _dir in (REPORTS_DIR, LOGS_DIR, OUTPUT_DIR):
    _dir.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Nmap / socket defaults
# ---------------------------------------------------------------------------
NMAP_BINARY = "nmap"          # Must be resolvable on PATH
DEFAULT_TIMEOUT = 300          # seconds, hard cap for a single scan
BANNER_GRAB_TIMEOUT = 3        # seconds, per-port socket timeout
BANNER_GRAB_THREADS = 20       # concurrent banner-grab workers

# Common ports used for quick banner grabbing when the user hasn't
# supplied a specific port list.
COMMON_BANNER_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

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
