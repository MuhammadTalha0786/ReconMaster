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
from logger import get_logger, log_error
from scanner import check_nmap_available

console = Console()
logger = get_logger()


def main() -> int:
    if any(flag in sys.argv for flag in ("-h", "--help", "--version")):
        return run_cli()

    if not check_nmap_available():
        console.print(
            "[bold red]Nmap was not found on PATH.[/bold red]\n"
            "Install Nmap from https://nmap.org/download.html and ensure "
            "it is accessible from your terminal, then try again."
        )
        return 1

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
