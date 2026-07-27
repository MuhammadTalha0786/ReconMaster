#!/usr/bin/env python3
"""
main.py
========
Entry point for ReconMaster — Advanced Network Reconnaissance Framework.

Run with no arguments for the interactive Rich menu, or with --cli for
scripted / non-interactive use. See cli.py --help for CLI options.

Usage:
    python main.py                # interactive menu
    python main.py --cli --target 10.0.0.5 --scan fast --format json
"""

from __future__ import annotations

import sys

from rich.console import Console

from cli import run_cli
from config import APP_VERSION
from environment import build_environment_report, check_nmap_version, format_environment_warning
from logger import get_logger, log_error, log_program_exit, log_program_start
from scanner import check_nmap_available

console = Console()
logger = get_logger()


def main() -> int:
    if any(flag in sys.argv for flag in ("-h", "--help", "--version")):
        return run_cli()

    log_program_start(logger, APP_VERSION)
    exit_code = _run()
    log_program_exit(logger, exit_code)
    return exit_code


def _show_environment_warning_if_needed() -> None:
    """
    A warning only — never a reason to stop ReconMaster from starting.
    Shown only when a project .venv exists and the current interpreter
    isn't it; running system Python or another environment on purpose is
    legitimate and shouldn't be treated as an error.
    """
    report = build_environment_report()
    warning = format_environment_warning(report)
    if warning:
        console.print(f"[yellow]{warning}[/yellow]\n")


def _check_nmap_and_warn() -> None:
    """
    Check Nmap availability and report it — but never block startup on
    Nmap's absence. Not every ReconMaster feature needs Nmap (banner
    grabbing is entirely socket-based), so refusing to start at all would
    make those features unreachable for no reason. Individual Nmap-
    dependent scans still fail cleanly on their own (scanner.py raises
    NmapNotFoundError, which menu.py/cli.py/job.py already catch and
    turn into a friendly message) rather than a raw traceback.
    """
    if check_nmap_available():
        nmap_version = check_nmap_version() or "detected"
        console.print(f"[green][+] Nmap detected: {nmap_version}[/green]")
        console.print("[green][+] Environment: OK[/green]\n")
    else:
        console.print(
            "[yellow][!] Nmap was not found on PATH.[/yellow]\n\n"
            "Nmap-dependent scan features will be unavailable.\n"
            "Some ReconMaster functionality may still be available.\n\n"
            "Install Nmap and restart ReconMaster to enable network scanning.\n"
        )


def _run() -> int:
    _show_environment_warning_if_needed()
    _check_nmap_and_warn()

    if "--cli" in sys.argv:
        return run_cli()

    # Default: interactive menu
    from menu import run_menu
    try:
        run_menu()
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user. Exiting.[/yellow]")
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        log_error(logger, f"Unhandled exception: {exc}")
        console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
