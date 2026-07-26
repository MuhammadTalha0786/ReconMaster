<p align="center">
  <img src="assets/logo_placeholder.png" alt="ReconMaster logo" width="160"/>
</p>

<h1 align="center">ReconMaster</h1>
<p align="center"><b>Advanced Network Reconnaissance Framework</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/badge/status-academic%20project-orange" />
</p>

---

## Description

**ReconMaster** is a professional, menu-driven Python framework that wraps
standard [Nmap](https://nmap.org) functionality behind a clean [Rich](https://github.com/Textualize/rich)
terminal interface. It was built as a BS Cyber Security university project
to demonstrate host discovery, port scanning, service/OS detection, NSE
scripting, and firewall rule-set analysis — with configurable timeouts,
multi-task scanning, and professional multi-format reporting on top.

> **Authorized use only.** ReconMaster is intended for authorized security
> testing, educational labs, and systems for which you have explicit
> permission to perform security assessments. It automates legitimate Nmap
> options selected by the user and does **not** implement malware,
> exploitation, persistence, or credential theft of any kind.

---

## Features

- 🎯 Host discovery, TCP/UDP port scanning (SYN, Connect, UDP, full, fast, top-N, custom ports/ranges)
- 🔍 Service & version detection, OS detection with optional traceroute
- 📡 Multi-threaded socket-based banner grabbing
- 🧩 NSE script support — single category, a custom script name, **or multiple categories combined into one Nmap invocation** (`--script default,safe,vuln`)
- 🧱 29 standard Nmap firewall/filtering-analysis techniques (see [Firewall Assessment Module](#firewall-assessment-module)) — selectable individually or **multiple at once**, with automatic conflict detection
- ⚡ Aggressive scan mode (`-A`) and validated custom Nmap command entry
- 🗂️ **Multi-Task Scan**: select several scan types in one go (`1,2,6,7`), run them in a sensible order, automatically skip redundant work (e.g. Aggressive Scan already covers service detection), and get one aggregated report
- ⏱️ **Configurable, scan-type-specific timeouts** — no more one-size-fits-all 300-second limit — plus Default / Custom / No-application-timeout modes
- ⚙️ **Settings menu**, persisted to `config.json` (timeout mode, default report format, verbose mode, color output)
- 📄 Reports in **TXT, XML, JSON, HTML, and PDF** — single-scan or aggregated multi-task reports, plus terminal-only output
- 🧾 Rotating daily logs of program start/exit, every command, target, timeout, duration, and error
- 🖥️ Interactive Rich menu **and** a scriptable `--cli` mode for automation
- 🛡️ Hardened input handling: no `eval()`, no `shell=True`, strict target/port/filename/script-name validation
- ✅ Unit-tested core logic (multi-selection parsing, timeout resolution, firewall combination validation, job orchestration, report generation) — see `tests/`

---

## Installation

```bash
git clone https://github.com/<your-username>/ReconMaster.git
cd ReconMaster
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Requirements

- Python 3.9+
- [Nmap](https://nmap.org/download.html) installed and available on your system `PATH`
- Linux, macOS, or Windows

Some scan types (SYN scan, OS detection, most firewall/filtering-analysis
techniques) require elevated privileges — run with `sudo` on Linux/macOS or
an Administrator terminal on Windows.

---

## Usage

**Interactive menu:**

```bash
python main.py
```

**Non-interactive CLI mode:**

```bash
python main.py --cli --target 192.168.1.10 --scan fast --format json
python main.py --cli --target scanme.nmap.org --scan aggressive --timeout 1200
python main.py --cli --target scanme.nmap.org --scan nse --nse-category vuln --timeout 0
```

`--timeout` accepts a positive number of seconds, or `0` for no application
timeout (ReconMaster waits indefinitely for Nmap). Omit it to use the
scan-type's default (see [Timeout System](#timeout-system)). Run
`python cli.py --help` for the full flag list.

### Menu Screenshots

*(place captured screenshots in `screenshots/` and reference them below)*

| Main Menu | Multi-Task Scan | Firewall Assessment |
|---|---|---|
| `screenshots/main_menu.png` | `screenshots/multi_task_scan.png` | `screenshots/firewall_options.png` |

---

## Timeout System

A single fixed timeout doesn't fit every scan — OS detection, firewall
assessment, and NSE scripts routinely need far longer than a quick host
discovery sweep. ReconMaster resolves the *application* timeout (how long
ReconMaster waits for Nmap before giving up) separately per scan type:

| Scan type | Default timeout |
|---|---|
| Host Discovery | 60s |
| Port Scan | 180s |
| Service/Version Detection | 300s |
| Banner Grabbing (socket-based) | 120s |
| OS Detection | 600s |
| Aggressive Scan | 1200s |
| Firewall Assessment | 1800s |
| NSE Script Scan | 1800s |
| Custom Nmap Command | Unlimited |

Three timeout modes are available from the Settings menu or the
Multi-Task Scan workflow:

1. **Default** — the per-scan-type values above
2. **Custom** — one user-supplied timeout (seconds) applied to every scan
3. **No application timeout** — ReconMaster waits indefinitely

If the application timeout is reached, ReconMaster terminates the Nmap
subprocess cleanly and reports it explicitly as **"application timeout
reached"** — never as "Nmap scan failed", since Nmap itself never got the
chance to finish. This is distinct from Nmap's own internal timing options
(`-T0`–`-T5`, `--host-timeout`), which still apply on Nmap's side if used.

---

## Multi-Task Scan

Instead of running one scan at a time, select several at once:

```
Select scan tasks
 1. Host Discovery
 2. Port Scan
 3. Service/Version Detection
 4. Banner Grabbing
 5. OS Detection
 6. NSE Script Scan
 7. Firewall Assessment
 8. Aggressive Scan
Select scan tasks: 1,2,6,7
```

Input like `1,2,2,99,4` is handled gracefully — invalid numbers and
duplicates are reported and dropped, and the valid selection is confirmed
before continuing. Selected tasks run in a fixed, sensible order (Host
Discovery → Port Scan → Service Detection → Banner Grabbing → OS Detection
→ NSE → Firewall Assessment → Aggressive Scan), and redundant work is
skipped automatically — e.g. Service/Version Detection is skipped if
Aggressive Scan is also selected, since `-A` already covers it. If one task
fails or times out, the rest still run; a summary reports how many tasks
completed, failed, timed out, or were skipped. One aggregated report
(with a section per task) is generated at the end, in as many formats as
you select — Nmap is never re-run just to produce another format.

NSE scripts and firewall techniques can also be multi-selected within this
flow; multiple NSE categories are combined into a single `--script`
invocation (e.g. `--script default,safe,vuln`) rather than run separately.

---

## Firewall Assessment Module

`firewall.py` implements 29 standard, publicly documented Nmap
filtering/firewall rule-set analysis techniques: ACK, Window, Maimon, FIN,
NULL, and Xmas scans; Idle and FTP Bounce scans; No Ping and five
ping-discovery methods; packet-crafting modifiers (fragmentation, custom
MTU, appended data, source port/routing, decoys, MAC/IP/interface
spoofing, custom TTL, bad checksums); two IDS-evasion-friendly timing
templates; and an IP protocol scan.

**These techniques do not guarantee bypassing a firewall or IDS/IPS.**
They are diagnostic tools that reveal how a target's filtering responds to
different packet types and scan conditions — nothing more. Results should
always be interpreted by a qualified analyst.

Multiple techniques can be selected at once (e.g. `4,1,15` for FIN + ACK +
Fragment). Since Nmap only accepts one scan-type flag per invocation,
ReconMaster automatically detects incompatible combinations (e.g. two scan
types, or "No Ping" combined with a ping-discovery method) and splits them
into separate authorized analysis tasks rather than generating an invalid
Nmap command — while combining everything that *can* safely run together
(one scan type + any number of ping methods and packet-crafting modifiers)
into a single invocation.

---

## Output Formats

| Format | Description | Status |
|---|---|---|
| Terminal | Printed directly to the console, not saved | ✅ |
| TXT | Plain-text summary report | ✅ |
| XML | Structured, machine-parseable report | ✅ |
| JSON | Structured report for tooling/integration | ✅ |
| HTML | Styled, shareable report | ✅ |
| PDF | Polished report suitable for submission/print | ✅ Fixed and tested (see Troubleshooting) |

Reports are written to `reports/`, timestamped by default
(`scan_<target>_YYYY_MM_DD_HHMMSS.<ext>`), or under a filename you supply
— filenames are sanitized so they can never write outside `reports/`.
Multi-task scans produce one **aggregated** report with a numbered section
per task plus a completed/failed/timed-out/skipped summary.

## Report Examples

See `sample_reports/` for example single-scan reports in all five formats.

---

## Troubleshooting

- **"Nmap was not found on PATH"** — install Nmap and confirm `nmap --version` works in your terminal.
- **Permission denied on SYN scan / OS detection / most firewall techniques** — these need raw sockets; run with `sudo` (Linux/macOS) or an Administrator terminal (Windows).
- **"Application timeout reached"** — this means ReconMaster stopped waiting, not that Nmap failed. Increase the timeout via Settings, or choose "Custom"/"No application timeout".
- **PDF report looked broken in an old build** — earlier versions could crash on scan output containing `<`, `>`, or `&` (common in HTTP banners). This is fixed: all report formats now escape scan-derived content before rendering (see `tests/test_reconmaster.py` for the regression test).
- **A firewall technique selection was split into multiple scans** — this is expected when you select two mutually exclusive scan types (e.g. FIN + ACK) or "No Ping" alongside a ping-discovery method; ReconMaster tells you why and runs them separately rather than building an invalid Nmap command.

---

## Disclaimer

ReconMaster is intended **only** for authorized security testing, academic
coursework, and environments you own or have explicit written permission to
test (e.g. `scanme.nmap.org`, a personal lab, or a CTF range). Scanning
networks or hosts without authorization may be illegal in your jurisdiction.
The author and contributors accept no liability for misuse of this tool.

---

## License

Released under the [MIT License](LICENSE).

---

## Future Improvements

- Native Nmap XML parsing throughout (beyond the current regex-based report parser)
- Scan result diffing between runs (change detection over time)
- Optional integration with `python-nmap` for richer structured parsing
- Scheduled/recurring scan support with historical trend reports
- Export to SIEM-friendly formats (CEF/Syslog)
- CLI parity for multi-task/multi-NSE/multi-firewall selection (currently richest in the interactive menu; CLI supports single-scan `--timeout` today)

---

## Author

**Talha**
BS Cyber Security, HITEC University Taxila
Built as part of coursework in network security and Python development.
