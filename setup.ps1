# setup.ps1 — ReconMaster environment setup (Windows PowerShell)
#
# Creates a project-local virtual environment (.venv), installs
# requirements.txt into it, and verifies the critical dependencies
# (ReportLab for PDF reports, Nmap for scanning) are available.
#
# Safe by design:
#   - .venv is always created inside the project directory (resolved
#     from this script's own location), never anywhere else.
#   - Never installs Python packages globally/system-wide.
#   - Does not require Administrator privileges.
#   - Idempotent — running it again reuses the existing .venv.
#
# Usage (from an ordinary PowerShell prompt):
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\setup.ps1

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$VenvDir = Join-Path $ScriptDir ".venv"
$MinPyMajor = 3
$MinPyMinor = 9

function Write-Info($msg) { Write-Host "[*] $msg" }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[x] $msg" -ForegroundColor Red }

# --- 1 & 2. Detect Python, preferring the "py" launcher -----------------
$PythonCmd = $null
foreach ($candidate in @("py", "python", "python3")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $PythonCmd = $candidate
        break
    }
}

if (-not $PythonCmd) {
    Write-Err "Python was not found on PATH."
    Write-Err "Install Python $MinPyMajor.$MinPyMinor+ from https://www.python.org/downloads/ and re-run this script."
    exit 1
}
Write-Info "Using Python launcher: $PythonCmd"

# --- 3. Verify Python version --------------------------------------------
try {
    $PyVersionOutput = & $PythonCmd -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
} catch {
    $PyVersionOutput = $null
}

if (-not $PyVersionOutput) {
    Write-Err "Could not determine the Python version for '$PythonCmd'."
    exit 1
}

$PyParts = $PyVersionOutput.Trim().Split(".")
$PyMajor = [int]$PyParts[0]
$PyMinor = [int]$PyParts[1]

if (($PyMajor -lt $MinPyMajor) -or (($PyMajor -eq $MinPyMajor) -and ($PyMinor -lt $MinPyMinor))) {
    Write-Err "Python $PyVersionOutput was found, but ReconMaster requires $MinPyMajor.$MinPyMinor+."
    exit 1
}
Write-Ok "Python $PyVersionOutput detected ($PythonCmd) — meets the $MinPyMajor.$MinPyMinor+ requirement."

# --- 4 & 5. Detect Nmap, explain how to install if missing ---------------
$NmapCmd = Get-Command nmap -ErrorAction SilentlyContinue
if ($NmapCmd) {
    $NmapVersionLine = (& nmap --version 2>$null | Select-Object -First 1)
    Write-Ok "Nmap detected: $NmapVersionLine"
} else {
    Write-Warn "Nmap was not found on PATH. ReconMaster requires Nmap to perform scans."
    Write-Warn "Download and install Nmap from: https://nmap.org/download.html"
    Write-Warn "During installation, ensure 'Add Nmap to PATH' (or similar) is selected."
    Write-Warn "Continuing setup — Nmap can be installed later; ReconMaster will check again at startup."
}

# --- 6. Create a project-local virtual environment (.venv\) -------------
if ((Test-Path $VenvDir) -and (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
    Write-Ok "Existing virtual environment found at $VenvDir — reusing it."
} else {
    Write-Info "Creating virtual environment at $VenvDir ..."
    & $PythonCmd -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to create the virtual environment."
        exit 1
    }
    Write-Ok "Virtual environment created."
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Err "Virtual environment appears corrupt (no python.exe at $VenvPython)."
    Write-Err "Remove $VenvDir and re-run this script."
    exit 1
}

# --- 7. Upgrade pip inside the venv (never globally) ---------------------
Write-Info "Upgrading pip inside the virtual environment..."
& $VenvPython -m pip install --upgrade pip --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Failed to upgrade pip — continuing with the existing version."
}

# --- 8. Install requirements.txt into the venv ---------------------------
$RequirementsPath = Join-Path $ScriptDir "requirements.txt"
if (-not (Test-Path $RequirementsPath)) {
    Write-Err "requirements.txt not found in $ScriptDir."
    exit 1
}
Write-Info "Installing dependencies from requirements.txt ..."
& $VenvPython -m pip install -r $RequirementsPath --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Err "Dependency installation failed. Review the pip output above."
    exit 1
}
Write-Ok "Dependencies installed."

# --- 9 & 10. Verify critical dependencies, ReportLab specifically --------
Write-Info "Verifying critical Python dependencies..."
$DepCheckScript = @"
import importlib.util
import sys

required = ['rich', 'colorama', 'reportlab']
missing = [m for m in required if importlib.util.find_spec(m) is None]

if missing:
    print('[x] Missing required modules: ' + ', '.join(missing), file=sys.stderr)
    sys.exit(1)

print('[+] rich, colorama, and reportlab are all importable.')
print('[+] ReportLab specifically verified (required for PDF report generation).')
"@
$DepCheckScript | & $VenvPython -
if ($LASTEXITCODE -ne 0) {
    Write-Err "One or more required Python dependencies are missing after installation."
    exit 1
}

# --- 11. Verify Nmap availability (re-check, non-fatal) -------------------
if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Ok "Nmap availability re-confirmed."
} else {
    Write-Warn "Nmap still not found. ReconMaster will run, but scans will fail until Nmap is installed."
}

# --- Lightweight import check of ReconMaster's own modules ----------------
Write-Info "Running a lightweight import check of ReconMaster's modules..."
$ImportCheckScript = @"
import sys
sys.path.insert(0, r'$ScriptDir')
import config, settings, utils, logger, scanner, banner, firewall, nse, parser, job, report, environment, cli, menu, main
print('[+] All ReconMaster modules import cleanly.')
"@
$ImportCheckScript | & $VenvPython -
if ($LASTEXITCODE -ne 0) {
    Write-Err "ReconMaster's own modules failed to import — see the traceback above."
    exit 1
}
Write-Ok "Import check passed."

# --- 12. Final success output ---------------------------------------------
Write-Host ""
Write-Host "ReconMaster setup completed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "Activate:"
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "Run:"
Write-Host "    python main.py"
Write-Host ""
Write-Host "If PowerShell blocks script execution, run this once for the current"
Write-Host "process only (does not change your system-wide execution policy):"
Write-Host "    Set-ExecutionPolicy -Scope Process Bypass"
Write-Host ""
