"""
menu.py
========
Interactive terminal menu built with Rich. Drives the full ReconMaster
workflow: target entry, scan-type selection, execution, and report
generation. This is the primary user-facing interface (invoked from
main.py).

Two workflows are offered:
  - Quick single-task items (1-9): unchanged single-scan behavior from
    earlier versions, now using the configurable per-scan-type timeout.
  - "Multi-Task Scan" (10): select several tasks, NSE scripts, and/or
    firewall techniques at once; ReconMaster runs them in a sensible
    order, skips redundant work, and produces one aggregated report.
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
from job import ScanJob, ScanTask, TASK_LABELS, TASK_ORDER, TaskStatus, order_tasks, run_job, skip_redundant_tasks
from report import (
    build_job_report_data, build_report_data, generate_all_formats,
    generate_job_reports, generate_report,
)
from scanner import (
    NmapNotFoundError, ScanTimeoutError, aggressive_scan_args, custom_command_args,
    host_discovery_args, nse_multi_script_args, nse_script_args, os_detection_args,
    port_scan_args, run_nmap_with_xml, service_detection_args,
)
from settings import Settings, load_settings, resolve_timeout, save_settings
from utils import (
    parse_multi_selection, sanitize_custom_args, validate_port_spec, validate_target,
    validate_timeout_value,
)

console = Console()

MULTI_TASK_KEYS = TASK_ORDER
MULTI_TASK_LABELS = TASK_LABELS
OUTPUT_FORMAT_KEYS = ["txt", "xml", "json", "html", "pdf"]


def print_banner() -> None:
    width = 56
    console.print(f"[cyan]{'=' * width}[/cyan]")
    console.print(f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]".center(width + 9))
    console.print(f"[dim]{APP_SUBTITLE}[/dim]".center(width + 9))
    console.print(f"[cyan]{'=' * width}[/cyan]")


def prompt_target() -> Optional[str]:
    target = Prompt.ask("[bold yellow]Target[/bold yellow] (IP / hostname / CIDR)").strip()
    if not validate_target(target):
        console.print("[red]Invalid target. Please enter a valid IP, hostname, or CIDR range.[/red]")
        return None
    return target


def main_menu_table() -> Table:
    table = Table(title=f"{APP_NAME} — Main Menu", show_header=False, border_style="cyan")
    items = [
        ("1", "Host Discovery"), ("2", "Port Scan"), ("3", "Service Version Detection"),
        ("4", "Banner Grabbing"), ("5", "OS Detection"), ("6", "NSE Script Scan"),
        ("7", "Firewall Assessment"), ("8", "Aggressive Scan"), ("9", "Custom Nmap Command"),
        ("10", "Multi-Task Scan (select several of the above at once)"),
        ("11", "Settings"), ("12", "Exit"),
    ]
    for num, label in items:
        table.add_row(f"[bold]{num}.[/bold]", label)
    return table


# ---------------------------------------------------------------------------
# Shared single-task execution path (quick menu items 1-9)
# ---------------------------------------------------------------------------

def _run_and_report(target: str, args: List[str], label: str, timeout_key: str, settings: Settings) -> None:
    """Run a single Nmap invocation, show output, offer to save a report."""
    timeout = resolve_timeout(timeout_key, settings)
    try:
        console.print(f"[cyan]Running {label} against {target}...[/cyan]")
        result = run_nmap_with_xml(target, args, timeout=timeout)
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
    choice = Prompt.ask("Select output format", choices=list(REPORT_FORMATS.keys()), default="2")
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


def handle_host_discovery(target: str, settings: Settings) -> None:
    _run_and_report(target, host_discovery_args(), "Host Discovery", "host_discovery", settings)


def handle_port_scan(target: str, settings: Settings) -> None:
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
    _run_and_report(target, port_scan_args(mode, ports), "Port Scan", "port_scan", settings)


def handle_service_detection(target: str, settings: Settings) -> None:
    console.print("1. Version Detection  2. Version + Default Scripts  3. Service Enumeration")
    choice = Prompt.ask("Choose", choices=["1", "2", "3"])
    mode_map = {"1": "version", "2": "version_default_scripts", "3": "enumeration"}
    _run_and_report(target, service_detection_args(mode_map[choice]), "Service Detection",
                     "service_detection", settings)


def handle_banner_grabbing(target: str, settings: Settings) -> None:
    console.print(f"[cyan]Grabbing banners on {target}...[/cyan]")
    results = banner_mod.grab_banners(target)
    table = Table(title="Banner Grab Results")
    table.add_column("Port")
    table.add_column("Reachable")
    table.add_column("Banner")
    for r in results:
        table.add_row(str(r.port), "yes" if r.reachable else "no", r.banner or "-")
    console.print(table)


def handle_os_detection(target: str, settings: Settings) -> None:
    traceroute = Prompt.ask("Include traceroute?", choices=["y", "n"], default="n") == "y"
    _run_and_report(target, os_detection_args(traceroute), "OS Detection", "os_detection", settings)


def handle_nse_scan(target: str, settings: Settings) -> None:
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

    _run_and_report(target, args, "NSE Script Scan", "nse_scan", settings)


def handle_firewall_menu(target: str, settings: Settings) -> None:
    techniques = firewall_mod.describe_techniques()
    for i, t in enumerate(techniques, start=1):
        console.print(f"{i:2}. {t.description}")
    choice = Prompt.ask("Choose technique", choices=[str(i) for i in range(1, len(techniques) + 1)])
    tech = techniques[int(choice) - 1]

    value = None
    if tech.key in firewall_mod.TECHNIQUES_REQUIRING_VALUE:
        explicit_required = tech.key in firewall_mod.REQUIRES_EXPLICIT_VALUE
        prompt_text = (
            f"Enter value for {tech.key} (required)" if explicit_required
            else f"Enter value for {tech.key} (blank for default)"
        )
        while True:
            raw = Prompt.ask(prompt_text, default="").strip()
            if firewall_mod.validate_technique_value(tech.key, raw):
                value = raw or None
                break
            if explicit_required and not raw:
                console.print(f"[red]{tech.key} requires a value — it has no safe default.[/red]")
            else:
                console.print(f"[red]Invalid value for {tech.key}. Please try again.[/red]")

    args = firewall_mod.build_firewall_args(tech.key, value)
    console.print(
        "[dim]Note: this is a standard Nmap filtering-analysis technique, not a "
        "guaranteed firewall/IDS bypass.[/dim]"
    )
    _run_and_report(target, args, f"Firewall Assessment ({tech.key})", "firewall_assessment", settings)


def handle_aggressive_scan(target: str, settings: Settings) -> None:
    _run_and_report(target, aggressive_scan_args(), "Aggressive Scan", "aggressive_scan", settings)


def handle_custom_command(target: str, settings: Settings) -> None:
    raw = Prompt.ask("Enter additional Nmap arguments (e.g. -sV -p 1-500)")
    sanitized = sanitize_custom_args(raw)
    if not sanitized:
        console.print("[red]Rejected: input contains disallowed characters.[/red]")
        return
    _run_and_report(target, custom_command_args(sanitized), "Custom Scan", "custom_command", settings)


# ---------------------------------------------------------------------------
# Multi-task scan workflow
# ---------------------------------------------------------------------------

def _select_multi(prompt_label: str, options: List[str], option_labels: Optional[List[str]] = None) -> List[int]:
    """
    Generic multi-select prompt: shows a numbered list, accepts
    comma/space-separated selections, reports invalid tokens and
    duplicates, and re-prompts until at least one valid selection is
    made (or the user enters nothing to select none, where permitted
    by the caller).
    """
    labels = option_labels or options
    for i, label in enumerate(labels, start=1):
        console.print(f"{i:2}. {label}")

    while True:
        raw = Prompt.ask(f"[bold]{prompt_label}[/bold]").strip()
        result = parse_multi_selection(raw, range(1, len(options) + 1))
        if result.invalid:
            console.print(f"[red]Invalid selection(s): {', '.join(result.invalid)}[/red]")
        if result.duplicates:
            console.print(f"[yellow]Duplicate selection(s) ignored: {', '.join(str(d) for d in result.duplicates)}[/yellow]")
        if result.selected:
            console.print(f"[green]Selected:[/green] {','.join(str(s) for s in result.selected)}")
            return result.selected
        console.print("[red]No valid selections — please choose at least one.[/red]")


def _select_timeout_mode(settings: Settings) -> None:
    console.print("Timeout:\n  1. Default\n  2. Custom\n  3. No application timeout")
    choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")
    if choice == "1":
        settings.timeout_mode = "default"
    elif choice == "3":
        settings.timeout_mode = "unlimited"
    else:
        settings.timeout_mode = "custom"
        while True:
            raw = Prompt.ask("Enter timeout in seconds")
            value = validate_timeout_value(raw)
            if value is not None:
                settings.custom_timeout_seconds = value
                break
            console.print("[red]Invalid timeout — enter a positive whole number of seconds.[/red]")


def run_multi_task_scan(target: str, settings: Settings) -> None:
    """The full multi-task workflow: select tasks, NSE scripts, firewall
    techniques, timeout mode, and output formats; run them as one
    ScanJob; show progress; write one aggregated report."""
    console.print(Panel("Multi-Task Scan", style="bold cyan"))

    selected_indices = _select_multi("Select scan tasks", MULTI_TASK_KEYS,
                                      [MULTI_TASK_LABELS[k] for k in MULTI_TASK_KEYS])
    selected_keys = [MULTI_TASK_KEYS[i - 1] for i in selected_indices]

    notes: List[str] = []
    tasks: List[ScanTask] = []

    nse_category_keys: List[str] = []
    if "nse_scan" in selected_keys:
        categories = nse_mod.list_categories()
        nse_indices = _select_multi("Select NSE script categories", categories,
                                     [c.capitalize() for c in categories])
        nse_category_keys = [categories[i - 1] for i in nse_indices]

    firewall_selected_keys: List[str] = []
    firewall_values: dict = {}
    if "firewall_assessment" in selected_keys:
        fw_techniques = firewall_mod.describe_techniques()
        fw_indices = _select_multi(
            "Select firewall/filtering techniques", [t.key for t in fw_techniques],
            [t.description for t in fw_techniques],
        )
        firewall_selected_keys = [fw_techniques[i - 1].key for i in fw_indices]
        for key in firewall_selected_keys:
            if key not in firewall_mod.TECHNIQUES_REQUIRING_VALUE:
                continue
            explicit_required = key in firewall_mod.REQUIRES_EXPLICIT_VALUE
            prompt_text = f"Value for {key} (required)" if explicit_required else f"Value for {key} (blank for default)"
            while True:
                val = Prompt.ask(prompt_text, default="").strip()
                if firewall_mod.validate_technique_value(key, val):
                    if val:
                        firewall_values[key] = val
                    break
                if explicit_required and not val:
                    console.print(f"[red]{key} requires a value — it has no safe default.[/red]")
                else:
                    console.print(f"[red]Invalid value for {key}. Please try again.[/red]")

    _select_timeout_mode(settings)

    format_indices = _select_multi("Select output formats", OUTPUT_FORMAT_KEYS,
                                    [f.upper() for f in OUTPUT_FORMAT_KEYS])
    output_formats = [OUTPUT_FORMAT_KEYS[i - 1] for i in format_indices]

    # Build the ordered task list.
    ordered_keys = order_tasks(selected_keys)
    for key in ordered_keys:
        if key == "host_discovery":
            tasks.append(ScanTask("host_discovery", MULTI_TASK_LABELS[key], host_discovery_args(),
                                   resolve_timeout("host_discovery", settings)))
        elif key == "port_scan":
            tasks.append(ScanTask("port_scan", MULTI_TASK_LABELS[key], port_scan_args("fast"),
                                   resolve_timeout("port_scan", settings)))
        elif key == "service_detection":
            tasks.append(ScanTask("service_detection", MULTI_TASK_LABELS[key], service_detection_args("version"),
                                   resolve_timeout("service_detection", settings)))
        elif key == "banner_grab":
            # Socket-based, not an Nmap invocation — job.run_job() branches
            # on task_type to run this via banner.grab_banners() instead
            # of scanner.run_nmap_with_xml(), but it's still a first-class
            # ScanTask with full PENDING/RUNNING/COMPLETED/FAILED/TIMEOUT
            # status, progress display, and report representation.
            tasks.append(ScanTask("banner_grab", MULTI_TASK_LABELS[key], [],
                                   resolve_timeout("banner_grab", settings), task_type="banner_grab"))
        elif key == "os_detection":
            tasks.append(ScanTask("os_detection", MULTI_TASK_LABELS[key], os_detection_args(),
                                   resolve_timeout("os_detection", settings)))
        elif key == "nse_scan":
            tasks.append(ScanTask("nse_scan", MULTI_TASK_LABELS[key], nse_multi_script_args(nse_category_keys),
                                   resolve_timeout("nse_scan", settings)))
        elif key == "firewall_assessment":
            plan = firewall_mod.validate_firewall_combination(firewall_selected_keys)
            notes.extend(plan.notes)
            for group in plan.groups:
                if not group:
                    continue
                group_args = firewall_mod.build_args_for_group(group, firewall_values)
                group_label = f"Firewall Assessment ({', '.join(group)})"
                tasks.append(ScanTask("firewall_assessment", group_label, group_args,
                                       resolve_timeout("firewall_assessment", settings)))
        elif key == "aggressive_scan":
            tasks.append(ScanTask("aggressive_scan", MULTI_TASK_LABELS[key], aggressive_scan_args(),
                                   resolve_timeout("aggressive_scan", settings)))

    skip_redundant_tasks(tasks, notes)

    total = len(tasks)

    def on_progress(job: ScanJob, task: ScanTask) -> None:
        idx = job.tasks.index(task) + 1
        console.print(f"[{idx}/{total}] {task.label:.<40} {task.status.value}")

    job = ScanJob(target=target, tasks=tasks, output_formats=output_formats)

    console.print(f"\n[bold]{APP_NAME} Scan[/bold]  Target: {target}\n")
    try:
        run_job(job, progress_callback=on_progress)
    except KeyboardInterrupt:
        console.print("[yellow]Multi-task scan interrupted by user.[/yellow]")

    # Banner grabbing (if selected) already ran as part of the job above —
    # display its results here rather than re-running it separately.
    banner_task = next((t for t in job.tasks if t.key == "banner_grab"), None)
    if banner_task is not None and banner_task.banners:
        table = Table(title="Banner Grab Results")
        table.add_column("Port")
        table.add_column("Reachable")
        table.add_column("Banner")
        for b in banner_task.banners:
            table.add_row(str(b["port"]), "yes" if b["reachable"] else "no", b["banner"] or "-")
        console.print(table)
    elif banner_task is not None and banner_task.status == TaskStatus.FAILED:
        console.print(f"[red]Banner grabbing failed: {banner_task.stderr}[/red]")

    counts = job.summary_counts()
    console.print(
        f"\nScan Summary — Completed: {counts['COMPLETED']}  Failed: {counts['FAILED']}  "
        f"Timed out: {counts['TIMEOUT']}  Skipped: {counts['SKIPPED']}\n"
    )
    if counts["FAILED"] or counts["TIMEOUT"]:
        console.print("[yellow]One or more tasks did not complete successfully; see the report for details.[/yellow]")
    else:
        console.print("[green]Scan completed successfully.[/green]")

    if Prompt.ask("Generate an aggregated report for this job?", choices=["y", "n"], default="y") == "y":
        filename = Prompt.ask("Filename (blank = auto timestamp)", default="").strip() or None
        data = build_job_report_data(job, notes=notes)
        try:
            paths = generate_job_reports(data, output_formats, filename)
            for p in paths:
                console.print(f"[green]Saved:[/green] {p}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Failed to generate report: {exc}[/red]")


# ---------------------------------------------------------------------------
# Settings menu
# ---------------------------------------------------------------------------

def run_settings_menu(settings: Settings) -> None:
    while True:
        console.print(Panel(
            f"1. Default Timeout (currently: {settings.timeout_mode})\n"
            f"2. Custom Timeout (currently: {settings.custom_timeout_seconds}s)\n"
            f"3. Unlimited Timeout\n"
            f"4. Default Report Format (currently: {settings.default_report_format})\n"
            f"5. Verbose Mode (currently: {settings.verbose_mode})\n"
            f"6. Color Output (currently: {settings.color_output})\n"
            f"7. Save Configuration\n"
            f"8. Back to Main Menu",
            title="Settings",
        ))
        choice = Prompt.ask("Choose", choices=[str(i) for i in range(1, 9)])
        if choice == "1":
            settings.timeout_mode = "default"
        elif choice == "2":
            settings.timeout_mode = "custom"
            while True:
                raw = Prompt.ask("Enter custom timeout in seconds")
                value = validate_timeout_value(raw)
                if value is not None:
                    settings.custom_timeout_seconds = value
                    break
                console.print("[red]Invalid timeout — enter a positive whole number of seconds.[/red]")
        elif choice == "3":
            settings.timeout_mode = "unlimited"
        elif choice == "4":
            fmt = Prompt.ask("Default report format", choices=["txt", "xml", "json", "html", "pdf"],
                              default=settings.default_report_format)
            settings.default_report_format = fmt
        elif choice == "5":
            settings.verbose_mode = not settings.verbose_mode
        elif choice == "6":
            settings.color_output = not settings.color_output
        elif choice == "7":
            if save_settings(settings):
                console.print("[green]Configuration saved to config.json[/green]")
            else:
                console.print("[red]Failed to save configuration.[/red]")
        elif choice == "8":
            break


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_menu() -> None:
    print_banner()
    settings = load_settings()

    target = None
    while target is None:
        target = prompt_target()

    single_task_handlers = {
        "1": handle_host_discovery, "2": handle_port_scan, "3": handle_service_detection,
        "4": handle_banner_grabbing, "5": handle_os_detection, "6": handle_nse_scan,
        "7": handle_firewall_menu, "8": handle_aggressive_scan, "9": handle_custom_command,
    }

    while True:
        console.print(main_menu_table())
        choice = Prompt.ask("Select Option", choices=[str(i) for i in range(1, 13)])

        if choice == "12":
            console.print("[cyan]Goodbye![/cyan]")
            break
        elif choice == "11":
            run_settings_menu(settings)
        elif choice == "10":
            try:
                run_multi_task_scan(target, settings)
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Returning to menu.[/yellow]")
        elif choice in single_task_handlers:
            try:
                single_task_handlers[choice](target, settings)
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Returning to menu.[/yellow]")
