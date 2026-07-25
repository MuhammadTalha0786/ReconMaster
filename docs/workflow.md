# Workflow

1. User launches ReconMaster (`main.py`) — Nmap availability is checked first.
2. User enters a target; it is validated (IP / hostname / CIDR).
3. User selects a scan type from the main menu.
4. The relevant module (`scanner.py`, `banner.py`, `firewall.py`, `nse.py`)
   builds the appropriate, validated Nmap argument list.
5. `scanner.run_nmap_with_xml()` executes Nmap via `subprocess` (no shell),
   capturing output and duration, and logging the run.
6. Results are displayed in the terminal via Rich.
7. User is offered a report; `parser.py` extracts structured data and
   `report.py` renders it into the chosen format(s) under `reports/`.
8. User returns to the main menu or exits.
