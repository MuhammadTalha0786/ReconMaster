# User Guide

## Starting ReconMaster
Run `python main.py` for the interactive menu, or `python main.py --cli`
for scripted usage.

## Entering a Target
You may enter:
- A single IPv4 or IPv6 address (e.g. `192.168.1.10`, `2001:db8::1`)
- A hostname (e.g. `scanme.nmap.org`)
- A CIDR range (e.g. `192.168.1.0/24`)

Invalid targets are rejected before any scan is attempted.

## Main Menu
```
1. Host Discovery              7. Firewall Assessment
2. Port Scan                   8. Aggressive Scan
3. Service Version Detection    9. Custom Nmap Command
4. Banner Grabbing             10. Multi-Task Scan
5. OS Detection                11. Settings
6. NSE Script Scan             12. Exit
```
Items 1-9 run one scan at a time, exactly as before. Item 10 is the new
multi-task workflow described below. Vulnerability scanning remains
available as the "vuln" NSE category under item 6 (or `--scan vuln` in
CLI mode).

## Multi-Task Scan (item 10)
1. Select scan tasks, e.g. `1,2,6,7` (comma or space separated; invalid
   numbers and duplicates are reported and dropped).
2. If NSE Script Scan (6) was selected, choose one or more script
   categories, e.g. `1,2,4` — combined into a single Nmap invocation.
3. If Firewall Assessment (7) was selected, choose one or more of the 29
   techniques, e.g. `4,1,15`. Incompatible combinations (two scan types,
   or No Ping with a ping method) are automatically split into separate
   tasks, with an on-screen explanation.
4. Choose a timeout mode: Default, Custom (enter seconds), or No
   application timeout.
5. Choose one or more output formats: TXT, XML, JSON, HTML, PDF.
6. Watch live progress per task (`[2/5] Port Scan ... RUNNING` →
   `COMPLETED`/`FAILED`/`TIMEOUT`/`SKIPPED`), then review the summary and
   save the aggregated report.

## Settings (item 11)
- **Default / Custom / Unlimited Timeout** — sets the active timeout mode.
- **Default Report Format** — used to pre-fill the format prompt.
- **Verbose Mode**, **Color Output** — display preferences.
- **Save Configuration** — persists all settings to `config.json` so they
  survive across runs.

## CLI Mode
```
python main.py --cli --target 192.168.1.10 --scan fast --format json
python main.py --cli --target 192.168.1.10 --scan aggressive --timeout 1200
python main.py --cli --target 192.168.1.10 --scan nse --nse-category vuln --timeout 0
```
`--timeout 0` means no application timeout. Omit `--timeout` to use the
scan type's configured default. Run `python cli.py --help` for the full
flag list.
