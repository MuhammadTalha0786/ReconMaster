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
scripting, and firewall rule-set analysis — with professional multi-format
reporting on top.

> **Scope:** ReconMaster is strictly a defensive / network-auditing tool. It
> automates legitimate Nmap options selected by the user. It does **not**
> implement malware, exploitation, persistence, credential theft, or payload
> generation of any kind.

---

## Features

- 🎯 Host discovery, TCP/UDP port scanning (SYN, Connect, UDP, full, fast, top-N, custom ports/ranges)
- 🔍 Service & version detection, OS detection with optional traceroute
- 📡 Multi-threaded socket-based banner grabbing
- 🧩 Full NSE script category support (default, safe, discovery, http, ftp, dns, ssh, ssl, smb, smtp, snmp, auth, broadcast, vuln, malware, or a custom script name)
- 🧱 Standard Nmap firewall / packet-crafting analysis options (ACK, Window, FIN, NULL, Xmas, Idle, fragmentation, custom MTU, MAC spoofing, source port) — documented as diagnostic techniques, not guaranteed bypass methods
- ⚡ Aggressive scan mode (`-A`) and validated custom Nmap command entry
- 📄 Reports in **TXT, XML, JSON, HTML, and PDF**, plus terminal-only output
- 🧾 Rotating daily logs of every command, duration, warning, and error
- 🖥️ Interactive Rich menu **and** a scriptable `--cli` mode for automation
- 🛡️ Hardened input handling: no `eval()`, no `shell=True`, strict target/argument validation

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

Some scan types (SYN scan, OS detection, firewall/packet-crafting options)
require elevated privileges — run with `sudo` on Linux/macOS or an
Administrator terminal on Windows.

---

## Usage

**Interactive menu:**

```bash
python main.py
```

**Non-interactive CLI mode:**

```bash
python main.py --cli --target 192.168.1.10 --scan fast --format json
python main.py --cli --target scanme.nmap.org --scan vuln --format all
```

Run `python cli.py --help` for the full list of CLI flags.

### Menu Screenshots

*(place captured screenshots in `screenshots/` and reference them below)*

| Main Menu | Port Scan | NSE Scan |
|---|---|---|
| `screenshots/main_menu.png` | `screenshots/port_scan.png` | `screenshots/nse_scan.png` |

---

## Example Scans

```bash
# Quick discovery sweep of a subnet
python main.py --cli --target 192.168.1.0/24 --scan discovery

# Full TCP port scan with an HTML report
python main.py --cli --target 10.0.0.5 --scan full --format html

# NSE vulnerability scripts against a lab target
python main.py --cli --target scanme.nmap.org --scan vuln --format pdf
```

---

## Output Formats

| Format | Description |
|---|---|
| Terminal | Printed directly to the console, not saved |
| TXT | Plain-text summary report |
| XML | Structured, machine-parseable report |
| JSON | Structured report for tooling/integration |
| HTML | Styled, shareable report |
| PDF | Polished report suitable for submission/print |

Reports are written to `reports/`, timestamped by default
(`scan_<target>_YYYY_MM_DD_HHMMSS.<ext>`), or under a filename you supply.

## Report Examples

See `sample_reports/` for example TXT, JSON, XML, HTML, and PDF-generation
output produced against a lab target.

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

---

## Author

**Talha**
BS Cyber Security, HITEC University Taxila
Built as part of coursework in network security and Python development.
