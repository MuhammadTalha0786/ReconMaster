"""
menu.py
========
Interactive terminal menu built with Rich. Drives the full ReconMaster
workflow: target entry, scan-type selection, execution, and report
generation. This is the primary user-facing interface (invoked from
main.py).
"""

from __future__ import annotations

from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

import banner as banner_mod
import firewall as firewall_mod
import nse as nse_mod
import parser as parser_mod
import scanner
from config import APP_NAME, APP_SUBTITLE, APP_VERSION, REPORT_FORMATS
from report import build_report_data, generate_all_formats, generate_report
from scanner import (
    NmapNotFoundError, ScanTimeoutError, aggressive_scan_args, custom_command_args,
    host_discovery_args, nse_script_args, os_detection_args, port_scan_args,
    run_nmap_with_xml, service_detection_args, vuln_scan_args,
)
from utils import sanitize_custom_args, validate_port_spec, validate_target

console = Console()


def print_banner() -> None:
    console.print(Panel.fit(
        f"[bold cyan]{APP_NAME}[/bold cyan] v{APP_VERSION}\n"
        f"[dim]{APP_SUBTITLE}[/dim]",
        border_style="cyan",
    ))


def prompt_target() -> Optional[str]:
    target = Prompt.ask("[bold yellow]Enter Target[/bold yellow] (IP / hostname / CIDR)").strip()
    if not validate_target(target):
        console.print("[red]Invalid target. Please enter a valid IP, hostname, or CIDR range.[/red]")
        return None
    return target


def main_menu_table() -> Table:
    table = Table(title=f"{APP_NAME} — Main Menu", show_header=False, border_style="cyan")
    items = [
        ("1", "Host Discovery"), ("2", "Port Scan"), ("3", "Service & Version Detection"),
        ("4", "Banner Grabbing"), ("5", "OS Detection"), ("6", "NSE Script Scan"),
        ("7", "Vulnerability Scan"), ("8", "Firewall Scan Options"), ("9", "Aggressive Scan"),
        ("10", "Custom Nmap Command"), ("11", "Report Options"), ("12", "Settings"), ("13", "Exit"),
    ]
    for num, label in items:
        table.add_row(f"[bold]{num}.[/bold]", label)
    return table


def _run_and_report(target: str, args: List[str], label: str) -> None:
    """Shared execution path: run nmap, show output, offer to save a report."""
    try:
        console.print(f"[cyan]Running {label} against {target}...[/cyan]")
        result = run_nmap_with_xml(target, args)
    except NmapNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    except ScanTimeoutError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    except KeyboardInterrupt:
        console.print("[yellow]Scan interrupted by user.[/yellow]")
        return

    if result.error_message and not result.raw_output:
        console.print(f"[red]Error: {result.error_message}[/red]")
        return

    console.print(Panel(result.raw_output or "(no output)", title=f"{label} Results", border_style="green"))
    result.open_ports = parser_mod.parse_open_ports(result.raw_output)

    if Prompt.ask("Save a report for this scan?", choices=["y", "n"], default="n") == "y":
        _report_flow(result)


def _report_flow(result: scanner.ScanResult) -> None:
    console.print(Table.grid())
    for key, fmt in REPORT_FORMATS.items():
        console.print(f"  {key}. {fmt.upper()}")
    choice = Prompt.ask("Select output format", choices=list(REPORT_FORMATS.keys()), default="7")
    fmt = REPORT_FORMATS[choice]

    filename = Prompt.ask("Filename (blank = auto timestamp)", default="").strip() or None

    os_guess = parser_mod.parse_os_guess(result.raw_output)
    data = build_report_data(result, os_guess=os_guess)

    if fmt == "terminal":
        console.print(Panel(result.raw_output, title="Terminal Report"))
        return

    try:
        if fmt == "all":
            paths = generate_all_formats(data, filename)
            for p in paths:
                console.print(f"[green]Saved:[/green] {p}")
        else:
            path = generate_report(data, fmt, filename)
            console.print(f"[green]Saved:[/green] {path}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Failed to generate report: {exc}[/red]")


def handle_host_discovery(target: str) -> None:
    _run_and_report(target, host_discovery_args(), "Host Discovery")


def handle_port_scan(target: str) -> None:
    console.print(
        "1. TCP SYN  2. TCP Connect  3. UDP  4. Full  5. Fast  "
        "6. Top100  7. Top1000  8. Specific Ports  9. Port Range"
    )
    choice = Prompt.ask("Choose port scan type", choices=[str(i) for i in range(1, 10)])
    mode_map = {
        "1": "syn", "2": "connect", "3": "udp", "4": "full", "5": "fast",
        "6": "top100", "7": "top1000", "8": "ports", "9": "range",
    }
    mode = mode_map[choice]
    ports = None
    if mode in ("ports", "range"):
        while True:
            ports = Prompt.ask("Enter ports (e.g. 22,80,443 or 1-1000)").strip()
            if validate_port_spec(ports):
                break
            console.print(
                "[red]Invalid port specification. Use comma-separated ports "
                "(22,80,443) and/or ranges (1-1000), each between 1-65535.[/red]"
            )
    _run_and_report(target, port_scan_args(mode, ports), "Port Scan")


def handle_service_detection(target: str) -> None:
    console.print("1. Version Detection  2. Version + Default Scripts  3. Service Enumeration")
    choice = Prompt.ask("Choose", choices=["1", "2", "3"])
    mode_map = {"1": "version", "2": "version_default_scripts", "3": "enumeration"}
    _run_and_report(target, service_detection_args(mode_map[choice]), "Service Detection")


def handle_banner_grabbing(target: str) -> None:
    console.print(f"[cyan]Grabbing banners on {target}...[/cyan]")
    results = banner_mod.grab_banners(target)
    table = Table(title="Banner Grab Results")
    table.add_column("Port")
    table.add_column("Reachable")
    table.add_column("Banner")
    for r in results:
        table.add_row(str(r.port), "yes" if r.reachable else "no", r.banner or "-")
    console.print(table)


def handle_os_detection(target: str) -> None:
    traceroute = Prompt.ask("Include traceroute?", choices=["y", "n"], default="n") == "y"
    _run_and_report(target, os_detection_args(traceroute), "OS Detection")


def handle_nse_scan(target: str) -> None:
    categories = nse_mod.list_categories()
    for i, cat in enumerate(categories, start=1):
        console.print(f"{i}. {cat.capitalize()}")
    console.print(f"{len(categories) + 1}. Individual Script")
    choice = Prompt.ask("Choose NSE category", choices=[str(i) for i in range(1, len(categories) + 2)])
    idx = int(choice) - 1

    if idx == len(categories):
        script_name = Prompt.ask("Enter script name(s), comma-separated")
        validated = nse_mod.validate_script_name(script_name)
        if not validated:
            console.print("[red]Invalid script name.[/red]")
            return
        args = nse_script_args("", custom_script=validated)
    else:
        args = nse_script_args(categories[idx])

    _run_and_report(target, args, "NSE Script Scan")


def handle_vuln_scan(target: str) -> None:
    _run_and_report(target, vuln_scan_args(), "Vulnerability Scan")


def handle_firewall_menu(target: str) -> None:
    techniques = firewall_mod.describe_techniques()
    for i, t in enumerate(techniques, start=1):
        console.print(f"{i}. {t.description}")
    choice = Prompt.ask("Choose technique", choices=[str(i) for i in range(1, len(techniques) + 1)])
    tech = techniques[int(choice) - 1]

    value = None
    if tech.key in ("idle", "mtu", "spoof_mac", "source_port"):
        value = Prompt.ask(f"Enter value for {tech.key} (blank for default)", default="").strip() or None

    args = firewall_mod.build_firewall_args(tech.key, value)
    console.print(
        "[dim]Note: this is a standard Nmap analysis technique, not a guaranteed "
        "firewall bypass.[/dim]"
    )
    _run_and_report(target, args, f"Firewall Scan ({tech.key})")


def handle_aggressive_scan(target: str) -> None:
    _run_and_report(target, aggressive_scan_args(), "Aggressive Scan")


def handle_custom_command(target: str) -> None:
    raw = Prompt.ask("Enter additional Nmap arguments (e.g. -sV -p 1-500)")
    sanitized = sanitize_custom_args(raw)
    if not sanitized:
        console.print("[red]Rejected: input contains disallowed characters.[/red]")
        return
    _run_and_report(target, custom_command_args(sanitized), "Custom Scan")


def run_menu() -> None:
    print_banner()

    target = None
    while target is None:
        target = prompt_target()

    handlers = {
        "1": handle_host_discovery, "2": handle_port_scan, "3": handle_service_detection,
        "4": handle_banner_grabbing, "5": handle_os_detection, "6": handle_nse_scan,
        "7": handle_vuln_scan, "8": handle_firewall_menu, "9": handle_aggressive_scan,
        "10": handle_custom_command,
    }

    while True:
        console.print(main_menu_table())
        choice = Prompt.ask("Select an option", choices=[str(i) for i in range(1, 14)])

        if choice == "13":
            console.print("[cyan]Goodbye![/cyan]")
            break
        elif choice == "11":
            console.print("[yellow]Run a scan first, then choose 'Save a report' at the prompt.[/yellow]")
        elif choice == "12":
            console.print(f"[dim]{APP_NAME} v{APP_VERSION} — settings are configured in config.py[/dim]")
        elif choice in handlers:
            try:
                handlers[choice](target)
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Returning to menu.[/yellow]")
