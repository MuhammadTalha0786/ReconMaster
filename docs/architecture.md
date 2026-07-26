# Architecture

ReconMaster is organized into small, single-responsibility modules:

| Module | Responsibility |
|---|---|
| `config.py` | Paths, constants, per-scan-type default timeouts, Nmap option maps |
| `settings.py` | Loads/saves user preferences to `config.json`; resolves the active timeout for a scan type given the current timeout mode |
| `utils.py` | Target/port/filename validation, multi-selection parsing, timeout-value validation, formatting helpers |
| `logger.py` | Rotating daily logging (program start/exit, commands, durations, warnings, errors) |
| `scanner.py` | Builds Nmap argument lists and executes them via `subprocess` (never `shell=True`) |
| `banner.py` | Concurrent socket-based banner grabbing (not Nmap-based) |
| `firewall.py` | 29 firewall/filtering-analysis techniques, their metadata, and combination-compatibility validation |
| `nse.py` | NSE script category mapping and script-name validation |
| `parser.py` | Best-effort text parsing of Nmap output for reports |
| `job.py` | `ScanTask`/`ScanJob` — multi-task orchestration, execution order, redundant-task skipping, per-task status |
| `report.py` | TXT / XML / JSON / HTML / PDF report generation — both single-scan and aggregated multi-task reports |
| `menu.py` | Interactive Rich-based terminal UI (quick single-task items + Multi-Task Scan + Settings) |
| `cli.py` | Non-interactive argparse-based CLI |
| `main.py` | Entry point; dispatches to menu or CLI; logs program start/exit |
| `tests/` | Unit tests covering the above, with `subprocess`/Nmap execution mocked out |

## Design Principles
- **No `shell=True`, ever.** All Nmap invocations pass a list of arguments
  directly to `subprocess.run`.
- **No `eval()`.** All user input is validated against explicit allow-lists.
- **Separation of concerns.** Scan-argument construction (`scanner.py`,
  `firewall.py`) is independent of execution (`scanner.run_nmap_with_xml`,
  `job.run_job`), which is independent of presentation (`menu.py`/`cli.py`).
- **One Nmap process per compatible unit of work.** Multiple NSE categories
  are combined into a single `--script a,b,c` invocation; multiple firewall
  techniques are combined into one invocation where Nmap supports it, and
  split into separate tasks only when techniques are genuinely incompatible
  (see `firewall.validate_firewall_combination`).
- **Graceful, per-task failure.** A failing or timed-out task never aborts
  the rest of a multi-task job (`job.run_job` catches per-task exceptions);
  a missing Nmap binary is the one exception that halts remaining tasks,
  since every subsequent task would fail identically.
- **Application timeout ≠ Nmap failure.** Reaching the configured
  application timeout is reported as exactly that, not as a scan failure.
