"""
environment.py
================
Cross-platform environment and dependency validation for ReconMaster:
Python interpreter/version, project .venv detection, required Python
module availability (especially ReportLab, needed for PDF reports),
and Nmap availability.

Every check here is read-only and side-effect-free (no installation,
no filesystem writes) — this module answers "what does the current
environment look like?", it never changes it. It's used by main.py to
show a one-time environment warning, and by menu.py/cli.py to give a
professional message instead of a raw traceback when an optional
dependency (ReportLab) is missing.
"""

from __future__ import annotations

import importlib.util
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from config import BASE_DIR, NMAP_BINARY

MIN_PYTHON_VERSION = (3, 9)

# Modules actually imported by ReconMaster's own code (see requirements.txt).
# ReconMaster invokes the nmap binary directly via subprocess (scanner.py)
# rather than through the python-nmap wrapper library, so that package is
# intentionally not tracked here.
REQUIRED_MODULES = ["rich", "colorama", "reportlab"]


@dataclass
class EnvironmentReport:
    """A point-in-time snapshot of the running environment."""
    python_executable: str
    python_version: str
    python_version_ok: bool
    venv_path: Path
    venv_exists: bool
    running_in_project_venv: bool
    missing_required_modules: List[str] = field(default_factory=list)
    nmap_available: bool = False
    nmap_version: str = ""


def get_project_venv_path() -> Path:
    """Return the expected .venv path for this project (BASE_DIR/.venv)."""
    return BASE_DIR / ".venv"


def is_running_in_project_venv(venv_path: Optional[Path] = None) -> bool:
    """
    Return True if the currently running Python interpreter belongs to
    this project's .venv.

    Deliberately compares `sys.prefix` (set from the venv's pyvenv.cfg)
    rather than resolving `sys.executable` — a venv's python binary is
    typically a symlink chain that ultimately resolves to the system
    interpreter (e.g. .venv/bin/python -> python3 -> /usr/bin/python3),
    so resolving the executable path would incorrectly report "not in
    venv" even when running via the venv's own interpreter. `sys.prefix`
    is set explicitly by the venv machinery and isn't affected by that
    symlink chain. Never raises — any path-resolution error is treated
    as "not running in the project venv".
    """
    venv_path = venv_path or get_project_venv_path()
    try:
        return Path(sys.prefix).resolve() == venv_path.resolve()
    except OSError:
        return False


def check_python_version(minimum: Tuple[int, int] = MIN_PYTHON_VERSION) -> bool:
    """Return True if the running interpreter meets the minimum version."""
    return sys.version_info[:2] >= minimum


def check_module_available(module_name: str) -> bool:
    """
    Return True if a module can be imported, without actually importing
    it (avoids side effects / import time cost from heavy dependencies
    like reportlab). Never raises.
    """
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def check_missing_modules(modules: List[str]) -> List[str]:
    """Return the subset of `modules` that are NOT importable."""
    return [m for m in modules if not check_module_available(m)]


def check_reportlab_available() -> bool:
    """Dedicated check since PDF report generation depends specifically
    on ReportLab and deserves its own clear diagnostic."""
    return check_module_available("reportlab")


def check_nmap_version(timeout: int = 10) -> Optional[str]:
    """
    Safely invoke `nmap --version` (argument list, never shell=True) and
    return the first line of its output, or None if Nmap isn't on PATH
    or doesn't run cleanly. Never raises.
    """
    if shutil.which(NMAP_BINARY) is None:
        return None
    try:
        completed = subprocess.run(
            [NMAP_BINARY, "--version"],
            capture_output=True, text=True, timeout=timeout, shell=False, check=False,
        )
        if completed.returncode == 0 and completed.stdout:
            return completed.stdout.splitlines()[0].strip()
        return None
    except (subprocess.TimeoutExpired, OSError):
        return None


def build_environment_report() -> EnvironmentReport:
    """Assemble a full EnvironmentReport in one call."""
    venv_path = get_project_venv_path()
    nmap_version = check_nmap_version()
    return EnvironmentReport(
        python_executable=sys.executable,
        python_version=platform.python_version(),
        python_version_ok=check_python_version(),
        venv_path=venv_path,
        venv_exists=venv_path.exists(),
        running_in_project_venv=is_running_in_project_venv(venv_path),
        missing_required_modules=check_missing_modules(REQUIRED_MODULES),
        nmap_available=nmap_version is not None,
        nmap_version=nmap_version or "",
    )


def format_environment_warning(report: EnvironmentReport) -> Optional[str]:
    """
    Return a formatted warning string if the user is running outside the
    project's .venv while a .venv DOES exist. Returns None (no warning)
    when .venv doesn't exist at all, or when the correct .venv
    interpreter is already active — running system Python or another
    environment intentionally is a legitimate choice, not an error.
    """
    if not report.venv_exists or report.running_in_project_venv:
        return None

    is_windows = platform.system() == "Windows"
    venv_python = report.venv_path / ("Scripts/python.exe" if is_windows else "bin/python")

    if is_windows:
        activate_cmd = r".\.venv\Scripts\Activate.ps1"
        direct_cmd = r".\.venv\Scripts\python.exe main.py"
    else:
        activate_cmd = "source .venv/bin/activate"
        direct_cmd = "./.venv/bin/python main.py"

    return (
        "[!] Environment Warning\n\n"
        "ReconMaster detected that you are running outside the project's virtual environment.\n\n"
        f"Current Python:\n    {report.python_executable}\n\n"
        f"Recommended Python:\n    {venv_python}\n\n"
        "Some features, including PDF report generation, may fail if dependencies\n"
        "are not installed in the current environment.\n\n"
        f"Recommended:\n    {activate_cmd}\n    python main.py\n\n"
        f"Or run directly:\n    {direct_cmd}"
    )


def format_missing_reportlab_message() -> str:
    """Professional, actionable message shown when PDF output is
    selected but ReportLab isn't installed — never a raw traceback."""
    return (
        "[!] PDF report generation requires ReportLab.\n\n"
        "ReportLab is not installed in the current Python environment.\n\n"
        "Recommended fix:\n"
        "    python -m pip install -r requirements.txt\n\n"
        "Or:\n"
        "    python -m pip install reportlab"
    )


def filter_available_formats(formats: List[str]) -> Tuple[List[str], Optional[str]]:
    """
    Given a list of requested report formats, drop "pdf" if ReportLab
    isn't available and return (remaining_formats, warning_message).
    warning_message is None if nothing was dropped. Other formats
    (txt/xml/json/html) have no external dependency and are never
    filtered here.
    """
    if "pdf" in formats and not check_reportlab_available():
        remaining = [f for f in formats if f != "pdf"]
        return remaining, format_missing_reportlab_message()
    return formats, None
