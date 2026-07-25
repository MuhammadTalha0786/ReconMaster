# Architecture

ReconMaster is organized into small, single-responsibility modules:

| Module | Responsibility |
|---|---|
| `config.py` | Paths, constants, Nmap option maps |
| `utils.py` | Target validation, input sanitization, formatting helpers |
| `logger.py` | Rotating daily logging (commands, durations, warnings, errors) |
| `scanner.py` | Builds Nmap argument lists and executes them via `subprocess` |
| `banner.py` | Concurrent socket-based banner grabbing |
| `firewall.py` | Firewall/packet-crafting technique metadata and argument builder |
| `nse.py` | NSE script category mapping and script-name validation |
| `parser.py` | Best-effort text parsing of Nmap output for reports |
| `report.py` | TXT / XML / JSON / HTML / PDF report generation |
| `menu.py` | Interactive Rich-based terminal UI |
| `cli.py` | Non-interactive argparse-based CLI |
| `main.py` | Entry point; dispatches to menu or CLI |

## Design Principles
- **No `shell=True`, ever.** All Nmap invocations pass a list of arguments
  directly to `subprocess.run`.
- **No `eval()`.** All user input is validated against explicit allow-lists.
- **Separation of concerns.** Scan-argument construction (`scanner.py`) is
  independent of execution, which is independent of presentation (`menu.py`/`cli.py`).
- **Graceful failure.** Missing Nmap, timeouts, permission errors, and
  interrupts are caught and reported without crashing the program.
