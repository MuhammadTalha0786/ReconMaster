#!/usr/bin/env bash
#
# setup.sh — ReconMaster environment setup (Linux / macOS)
#
# Creates a project-local virtual environment (.venv), installs
# requirements.txt into it, and verifies the critical dependencies
# (ReportLab for PDF reports, Nmap for scanning) are available.
#
# Safe by design:
#   - Never creates /venv at the filesystem root — always
#     <project-dir>/.venv, resolved from this script's own location.
#   - Never uses "sudo pip install" and never installs packages globally.
#   - Idempotent — running it again reuses the existing .venv rather
#     than breaking it.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh

set -u  # treat unset variables as errors (catches typos)
# Note: we deliberately do NOT use a blanket `set -e` for the whole
# script — several steps (e.g. detecting whether Nmap is installed)
# are expected to "fail" in a perfectly normal way, and we want to
# print a clear, specific message for those instead of aborting with a
# raw shell error. Steps where a failure IS fatal check $? explicitly
# and exit with a clear message.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"
MIN_PY_MAJOR=3
MIN_PY_MINOR=9

# --- output helpers -----------------------------------------------------
info()  { printf '[*] %s\n' "$1"; }
ok()    { printf '[+] %s\n' "$1"; }
warn()  { printf '[!] %s\n' "$1"; }
fail()  { printf '[x] %s\n' "$1" >&2; }

# --- 1. Detect OS (informational — script works on Linux and macOS) ----
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
case "$OS_NAME" in
    Linux)  info "Detected OS: Linux" ;;
    Darwin) info "Detected OS: macOS" ;;
    *)      warn "Unrecognized OS '$OS_NAME' — continuing, but this script is written for Linux/macOS." ;;
esac

# --- 2 & 3. Detect Python 3 and verify version --------------------------
PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    fail "Python 3 was not found on PATH."
    fail "Install Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ and re-run this script."
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
if [ -z "$PY_VERSION" ]; then
    fail "Could not determine the Python version for '$PYTHON_BIN'."
    exit 1
fi

PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION##*.}"
if [ "$PY_MAJOR" -lt "$MIN_PY_MAJOR" ] || { [ "$PY_MAJOR" -eq "$MIN_PY_MAJOR" ] && [ "$PY_MINOR" -lt "$MIN_PY_MINOR" ]; }; then
    fail "Python $PY_VERSION was found, but ReconMaster requires ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+."
    exit 1
fi
ok "Python $PY_VERSION detected ($PYTHON_BIN) — meets the ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ requirement."

# --- 4 & 5. Detect Nmap, explain how to install if missing --------------
if command -v nmap >/dev/null 2>&1; then
    NMAP_VERSION_LINE="$(nmap --version 2>/dev/null | head -n 1 || true)"
    ok "Nmap detected: ${NMAP_VERSION_LINE:-nmap is on PATH}"
else
    warn "Nmap was not found on PATH. ReconMaster requires Nmap to perform scans."
    # --- 6. Suggest the right package manager where reasonable ---------
    if command -v apt >/dev/null 2>&1; then
        warn "Detected an apt-based system (Debian/Ubuntu/Kali). Install Nmap with:"
        warn "    sudo apt update && sudo apt install -y nmap"
    elif command -v dnf >/dev/null 2>&1; then
        warn "Detected a dnf-based system (Fedora/RHEL). Install Nmap with:"
        warn "    sudo dnf install -y nmap"
    elif command -v pacman >/dev/null 2>&1; then
        warn "Detected an Arch-based system. Install Nmap with:"
        warn "    sudo pacman -S nmap"
    elif command -v brew >/dev/null 2>&1; then
        warn "Detected Homebrew (macOS). Install Nmap with:"
        warn "    brew install nmap"
    else
        warn "Install Nmap from https://nmap.org/download.html for your platform."
    fi
    warn "Continuing setup — Nmap can be installed later; ReconMaster will check again at startup."
fi

# --- 7. Create a project-local virtual environment (.venv) -------------
# Deliberately anchored to $SCRIPT_DIR, never "/venv" or any absolute
# path outside the project — idempotent: reused if it already exists.
if [ -d "$VENV_DIR" ] && [ -x "$VENV_DIR/bin/python" ]; then
    ok "Existing virtual environment found at $VENV_DIR — reusing it."
else
    info "Creating virtual environment at $VENV_DIR ..."
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
        fail "Failed to create the virtual environment. Ensure the 'venv' module is available"
        fail "(on Debian/Ubuntu: sudo apt install python3-venv), then re-run this script."
        exit 1
    fi
    ok "Virtual environment created."
fi

VENV_PYTHON="$VENV_DIR/bin/python"
if [ ! -x "$VENV_PYTHON" ]; then
    fail "Virtual environment appears corrupt (no python at $VENV_PYTHON)."
    fail "Remove $VENV_DIR and re-run this script."
    exit 1
fi

# --- 8. Upgrade pip inside the venv (never system-wide, never sudo) ----
info "Upgrading pip inside the virtual environment..."
if ! "$VENV_PYTHON" -m pip install --upgrade pip --quiet; then
    warn "Failed to upgrade pip — continuing with the existing version."
fi

# --- 9. Install requirements.txt into the venv --------------------------
if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
    fail "requirements.txt not found in $SCRIPT_DIR."
    exit 1
fi
info "Installing dependencies from requirements.txt ..."
if ! "$VENV_PYTHON" -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet; then
    fail "Dependency installation failed. Review the pip output above."
    exit 1
fi
ok "Dependencies installed."

# --- 10 & 11. Verify critical dependencies, ReportLab specifically ------
info "Verifying critical Python dependencies..."
"$VENV_PYTHON" - <<'PYEOF'
import importlib.util
import sys

required = ["rich", "colorama", "reportlab"]
missing = [m for m in required if importlib.util.find_spec(m) is None]

if missing:
    print(f"[x] Missing required modules: {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

print("[+] rich, colorama, and reportlab are all importable.")
print("[+] ReportLab specifically verified (required for PDF report generation).")
PYEOF
DEP_CHECK_STATUS=$?
if [ $DEP_CHECK_STATUS -ne 0 ]; then
    fail "One or more required Python dependencies are missing after installation."
    exit 1
fi

# --- 12. Verify Nmap availability (re-check, non-fatal) -----------------
if command -v nmap >/dev/null 2>&1; then
    ok "Nmap availability re-confirmed."
else
    warn "Nmap still not found. ReconMaster will run, but scans will fail until Nmap is installed."
fi

# --- 13. Lightweight import/dependency check of ReconMaster itself -----
info "Running a lightweight import check of ReconMaster's modules..."
if "$VENV_PYTHON" - <<PYEOF
import sys
sys.path.insert(0, "$SCRIPT_DIR")
import config, settings, utils, logger, scanner, banner, firewall, nse, parser, job, report, environment, cli, menu, main
print("[+] All ReconMaster modules import cleanly.")
PYEOF
then
    ok "Import check passed."
else
    fail "ReconMaster's own modules failed to import — see the traceback above."
    exit 1
fi

# --- 14. Final success output -------------------------------------------
echo ""
echo "ReconMaster setup completed successfully."
echo ""
echo "Activate:"
echo "    source .venv/bin/activate"
echo ""
echo "Run:"
echo "    python main.py"
echo ""
