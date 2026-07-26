# Workflow

## Single-task (menu items 1-9, or `--cli --scan ...`)
1. User launches ReconMaster (`main.py`) — Nmap availability is checked,
   and program start is logged.
2. User enters/validates a target.
3. User selects a scan type; the relevant module (`scanner.py`,
   `banner.py`, `firewall.py`, `nse.py`) builds a validated Nmap argument
   list.
4. `scanner.run_nmap_with_xml()` resolves the scan-type's timeout via
   `settings.resolve_timeout()`, then executes Nmap via `subprocess` (no
   shell), capturing output/duration and logging the run.
5. Results are displayed; the user is offered a report, generated via
   `report.py`.

## Multi-task (menu item 10)
1. User selects tasks, NSE scripts, and/or firewall techniques (all
   multi-select, validated via `utils.parse_multi_selection`).
2. Firewall selections are checked for scan-type/ping-method conflicts via
   `firewall.validate_firewall_combination()`, which groups compatible
   techniques into single invocations and splits incompatible ones.
3. `job.order_tasks()` sorts the selection into a fixed, sensible
   execution order; `job.skip_redundant_tasks()` marks tasks made
   redundant by a broader selection (e.g. Aggressive Scan already covers
   service detection) as `SKIPPED`.
4. `job.run_job()` executes each remaining task in turn, resolving each
   task's own timeout, catching per-task failures/timeouts without
   aborting the job, and reporting live progress.
5. `report.build_job_report_data()` + `report.generate_job_reports()`
   produce one aggregated report — sectioned by task — in every format
   the user selected, from the same job data (Nmap is not re-run per
   format).
