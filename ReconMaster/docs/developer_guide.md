# Developer Guide

## Adding a new scan mode
1. Add an argument-builder function in `scanner.py` (or `firewall.py`/`nse.py`
   if it's a firewall technique or NSE category) returning a `List[str]`.
2. Wire it into `menu.py` (interactive) and/or `cli.py` (`SCAN_CHOICES`).
3. Keep argument construction free of shell metacharacters; never build a
   shell string — always a `List[str]` passed to `subprocess.run`.

## Adding a new report format
1. Add a `generate_<format>(data: ReportData, filepath: Path) -> Path`
   function in `report.py`.
2. Register it in `_GENERATORS`.
3. Add the format to `config.REPORT_FORMATS` and to `cli.py`'s `--format` choices.

## Testing against a safe target
Use `scanme.nmap.org`, which Nmap's maintainers explicitly permit for
scan testing, or a local lab VM you control.

## Code style
- PEP8, type hints, and docstrings on every public function.
- No duplicated logic between `menu.py` and `cli.py` — both call into the
  same `scanner.py` / `report.py` functions.
