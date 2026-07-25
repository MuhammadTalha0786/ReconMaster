"""
cli.py
=======
Non-interactive command-line interface, for scripted / CI usage as an
alternative to the interactive Rich menu in menu.py.

Example:
    python main.py --cli --target 192.168.1.10 --scan fast --format json
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

import parser as parser_mod
from config import APP_NAME, APP_SUBTITLE, APP_VERSION
from report import build_report_data, generate_all_formats, generate_report
from scanner import (
    NmapNotFoundError, ScanTimeoutError, aggressive_scan_args, host_discovery_args,
    nse_script_args, os_detection_args, port_scan_args, run_nmap_with_xml,
    service_detection_args, vuln_scan_args,
)
from utils import validate_target

console = Console()

SCAN_CHOICES = {
    "discovery": lambda a: host_discovery_args(),
    "syn": lambda a: port_scan_args("syn"),
    "connect": lambda a: port_scan_args("connect"),
    "udp": lambda a: port_scan_args("udp"),
    "full": lambda a: port_scan_args("full"),
    "fast": lambda a: port_scan_args("fast"),
    "top100": lambda a: port_scan_args("top100"),
    "top1000": lambda a: port_scan_args("top1000"),
    "version": lambda a: service_detection_args("version"),
    "os": lambda a: os_detection_args(),
    "vuln": lambda a: vuln_scan_args(),
    "aggressive": lambda a: aggressive_scan_args(),
    "nse": lambda a: nse_script_args(a.nse_category or "default"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconmaster",
        description=f"{APP_NAME} v{APP_VERSION} — {APP_SUBTITLE}",
    )
    parser.add_argument("--cli", action="store_true", help="Run in non-interactive CLI mode")
    parser.add_argument("--target", help="Target IP, hostname, or CIDR range")
    parser.add_argument(
        "--scan", choices=list(SCAN_CHOICES.keys()), default="fast",
        help="Scan type to run",
    )
    parser.add_argument("--nse-category", help="NSE category when --scan nse is used")
    parser.add_argument("--ports", help="Specific ports/range for custom scans")
    parser.add_argument(
        "--format", choices=["txt", "json", "xml", "html", "pdf", "all"], default="txt",
        help="Report output format",
    )
    parser.add_argument("--filename", help="Base filename for the report (no extension)")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return parser


def run_cli(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.target:
        console.print("[red]--target is required in CLI mode.[/red]")
        return 2

    if not validate_target(args.target):
        console.print("[red]Invalid target supplied.[/red]")
        return 2

    scan_args = SCAN_CHOICES[args.scan](args)

    try:
        console.print(f"[cyan]Running '{args.scan}' scan against {args.target}...[/cyan]")
        result = run_nmap_with_xml(args.target, scan_args)
    except NmapNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    except ScanTimeoutError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1

    if result.error_message and not result.raw_output:
        console.print(f"[red]{result.error_message}[/red]")
        return 1

    console.print(result.raw_output)
    result.open_ports = parser_mod.parse_open_ports(result.raw_output)

    os_guess = parser_mod.parse_os_guess(result.raw_output)
    data = build_report_data(result, os_guess=os_guess)

    if args.format == "all":
        for path in generate_all_formats(data, args.filename):
            console.print(f"[green]Saved:[/green] {path}")
    else:
        path = generate_report(data, args.format, args.filename)
        console.print(f"[green]Saved:[/green] {path}")

    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
