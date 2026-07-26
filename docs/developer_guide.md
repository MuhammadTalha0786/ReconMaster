# Developer Guide

## Adding a new single-scan mode
1. Add an argument-builder function in `scanner.py` (or `firewall.py`/
   `nse.py` for a firewall technique or NSE category) returning `List[str]`.
2. Wire it into `menu.py` (a quick single-task handler) and/or `cli.py`'s
   `SCAN_CHOICES` (include its timeout-config key).
3. Never build a shell string — always a `List[str]` passed to
   `subprocess.run`.

## Adding a new multi-task option
1. Add the task's key/label to `job.TASK_ORDER` / `job.TASK_LABELS`.
2. In `menu.run_multi_task_scan()`, add a branch that appends a
   `ScanTask` with the right args and `resolve_timeout(key, settings)`.
3. If the task can make another task redundant, extend
   `job.skip_redundant_tasks()`.

## Adding a new firewall technique
1. Add its key/description to `firewall.FIREWALL_TECHNIQUES`.
2. Classify it in `SCAN_TYPE_TECHNIQUES`, `PING_TECHNIQUES`, or
   `MODIFIER_TECHNIQUES` (this drives combination validation).
3. Add its Nmap argument mapping in `scanner.firewall_scan_args()`.
4. If it takes a value, add its key to
   `firewall.TECHNIQUES_REQUIRING_VALUE`.

## Adding a new report format
1. Add `generate_<format>()` (single-scan) and/or
   `generate_aggregated_<format>()` (multi-task) in `report.py`.
2. Register it in `_GENERATORS` and/or `_AGGREGATED_GENERATORS`.
3. Escape all scan-derived content (`html.escape` for HTML,
   `xml.sax.saxutils.escape` for PDF `Paragraph()` text) — Nmap output
   routinely contains `<`, `>`, `&` in banners/service strings.
4. Add the format to `config.VALID_REPORT_FORMATS` and `cli.py`'s
   `--format` choices.

## Testing
Run the full suite (no live network or Nmap required — subprocess is
mocked):
```bash
python3 -m unittest discover -s tests -v
```
Use `scanme.nmap.org` (explicitly permitted by the Nmap project) or a
local lab VM for manual/live testing.

## Code style
- PEP8, type hints, and docstrings on every public function.
- No duplicated logic between `menu.py` and `cli.py` — both call into the
  same `scanner.py` / `job.py` / `report.py` functions.
