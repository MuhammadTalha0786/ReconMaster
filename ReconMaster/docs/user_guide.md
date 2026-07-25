# User Guide

## Starting ReconMaster
Run `python main.py` for the interactive menu, or `python main.py --cli`
for scripted usage.

## Entering a Target
You may enter:
- A single IP address (e.g. `192.168.1.10`)
- A hostname (e.g. `scanme.nmap.org`)
- A CIDR range (e.g. `192.168.1.0/24`)

Invalid targets are rejected before any scan is attempted.

## Main Menu Options
1. **Host Discovery** — ping-sweep style host-up detection (`-sn`)
2. **Port Scan** — SYN / Connect / UDP / full / fast / top-N / specific ports or range
3. **Service & Version Detection** — `-sV`, with or without default scripts
4. **Banner Grabbing** — concurrent socket-based banner capture
5. **OS Detection** — `-O`, optional traceroute
6. **NSE Script Scan** — choose a category or type a specific script name
7. **Vulnerability Scan** — runs the NSE `vuln` script category
8. **Firewall Scan Options** — ACK/Window/FIN/NULL/Xmas/Idle scans, fragmentation, custom MTU, MAC spoofing, source port
9. **Aggressive Scan** — `-A` (OS + version + scripts + traceroute)
10. **Custom Nmap Command** — enter validated, additional Nmap flags
11. **Report Options** — reminder that reports are offered after each scan
12. **Settings** — points to `config.py`
13. **Exit**

## Saving Reports
After any scan, you'll be asked whether to save a report. Choose a format
(Terminal, TXT, XML, JSON, HTML, PDF, or ALL) and optionally a filename —
leave it blank for an automatic timestamped name.

## CLI Mode
See the main README's "Usage" section, or run:
```bash
python cli.py --help
```
