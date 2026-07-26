"""
job.py
=======
Multi-task scan job orchestration. A ScanJob groups one or more
ScanTasks against a single target — e.g. Host Discovery + Port Scan +
NSE in one run — executes them in a safe, predictable order, and
collects per-task results (including failures and timeouts) without
letting any single task crash the whole job.

This is the layer that turns "run one Nmap command" (scanner.py) into
"run a user-selected set of reconnaissance steps and aggregate the
results for reporting" (menu.py / cli.py / report.py).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

import banner as banner_mod
from logger import get_logger, log_error, log_scan_end, log_scan_start, log_warning
from scanner import NmapNotFoundError, ScanTimeoutError, run_nmap_with_xml

logger = get_logger()

# Canonical execution order — running host discovery before a heavy port
# scan, and a targeted port scan before service detection/NSE, avoids
# redundant work and produces a more sensible report ordering.
TASK_ORDER = [
    "host_discovery",
    "port_scan",
    "service_detection",
    "banner_grab",
    "os_detection",
    "nse_scan",
    "firewall_assessment",
    "aggressive_scan",
]

TASK_LABELS = {
    "host_discovery": "Host Discovery",
    "port_scan": "Port Scan",
    "service_detection": "Service/Version Detection",
    "banner_grab": "Banner Grabbing",
    "os_detection": "OS Detection",
    "nse_scan": "NSE Script Scan",
    "firewall_assessment": "Firewall / Filtering Analysis",
    "aggressive_scan": "Aggressive Scan",
}


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"


@dataclass
class ScanTask:
    """A single scan step within a ScanJob.

    `task_type` distinguishes the execution path: "nmap" tasks run via
    scanner.run_nmap_with_xml (args is the Nmap argument list); "banner_grab"
    tasks run via banner.grab_banners (args is unused/empty — banner
    grabbing is socket-based, not an Nmap invocation) and populate
    `banners` with structured per-port results in addition to `stdout`
    (a human-readable rendering used by text-based report formats).
    """
    key: str                                   # e.g. "port_scan"
    label: str                                 # e.g. "Port Scan"
    args: List[str]                            # Nmap arguments (no target/binary)
    timeout: Optional[int] = None              # application timeout, None = unlimited
    task_type: str = "nmap"                    # "nmap" | "banner_grab"
    status: TaskStatus = TaskStatus.PENDING
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    return_code: Optional[int] = None
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    skip_reason: str = ""
    banners: List[Dict] = field(default_factory=list)


@dataclass
class ScanJob:
    """A group of ScanTasks run against a single target."""
    target: str
    tasks: List[ScanTask] = field(default_factory=list)
    output_formats: List[str] = field(default_factory=lambda: ["txt"])
    started_at: str = ""
    ended_at: str = ""
    duration_seconds: float = 0.0

    def summary_counts(self) -> Dict[str, int]:
        counts = {status.value: 0 for status in TaskStatus}
        for task in self.tasks:
            counts[task.status.value] += 1
        return counts


def order_tasks(selected_keys: List[str]) -> List[str]:
    """Return the selected task keys sorted into the canonical order."""
    ordered = [key for key in TASK_ORDER if key in selected_keys]
    # Preserve any keys not in the canonical list (shouldn't normally
    # happen) at the end, rather than silently dropping them.
    extras = [key for key in selected_keys if key not in TASK_ORDER]
    return ordered + extras


def skip_redundant_tasks(tasks: List[ScanTask], notes: List[str]) -> None:
    """
    Mark tasks SKIPPED where a later, broader task already covers them —
    e.g. Aggressive Scan (-A) already includes service/version detection,
    default-script NSE, and OS detection. Appends an explanation to
    `notes` for the report/CLI to display.
    """
    keys = {t.key for t in tasks if t.status != TaskStatus.SKIPPED}
    if "aggressive_scan" in keys:
        redundant = {"service_detection": "service/version detection", "os_detection": "OS detection"}
        for task in tasks:
            if task.key in redundant and task.status == TaskStatus.PENDING:
                task.status = TaskStatus.SKIPPED
                task.skip_reason = (
                    f"Aggressive Scan (-A) already performs {redundant[task.key]}; "
                    "skipped to avoid a redundant Nmap invocation."
                )
                notes.append(
                    f"{TASK_LABELS[task.key]} was skipped: {task.skip_reason}"
                )


def _execute_banner_task(target: str, task: ScanTask) -> None:
    """
    Execute a "banner_grab" task: socket-based, not an Nmap invocation.
    `task.timeout` is applied as an application-level deadline around the
    call (banner.grab_banners only bounds each individual port's socket
    timeout, not the overall call) — on expiry this raises
    ScanTimeoutError so the caller's normal timeout handling applies
    uniformly to Nmap and banner-grab tasks alike.

    Populates `task.banners` (structured per-port results, used directly
    by report.py for a dedicated Banner Information section) and
    `task.stdout` (a human-readable rendering for text-based formats).

    Note: unlike subprocess-based Nmap tasks, a timed-out banner grab
    cannot be forcibly killed — Python threads have no safe kill
    mechanism — so the background sockets may continue closing out on
    their own after ReconMaster stops waiting for them. The task is
    still correctly reported as TIMEOUT either way.
    """
    task.command = "socket banner grab (common service ports)"
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(banner_mod.grab_banners, target)
        try:
            results = future.result(timeout=task.timeout)
        except FutureTimeoutError:
            timeout_label = f"{task.timeout} seconds" if task.timeout else "the configured limit"
            raise ScanTimeoutError(
                f"Application timeout reached after {timeout_label} — banner "
                "grabbing was still running and ReconMaster stopped waiting. "
                "This does not mean the scan failed; increase the timeout if "
                "this target legitimately needs more time to respond."
            )

    task.banners = [
        {"port": r.port, "reachable": r.reachable, "banner": r.banner or ""}
        for r in results
    ]
    lines = [
        f"{b['port']}: {'reachable' if b['reachable'] else 'unreachable'}"
        + (f" — {b['banner']}" if b["banner"] else "")
        for b in task.banners
    ]
    task.stdout = "\n".join(lines) if lines else "(no banners captured)"
    task.status = TaskStatus.COMPLETED


def run_job(
    job: ScanJob,
    progress_callback: Optional[Callable[[ScanJob, ScanTask], None]] = None,
) -> ScanJob:
    """
    Execute every non-skipped task in `job`, in order, updating each
    task's status/timing/output in place. A failure or timeout in one
    task never aborts the remaining tasks — each is caught, logged, and
    recorded on that task alone.

    `progress_callback`, if given, is called after each task starts and
    after it finishes, so a caller (menu.py) can render live progress.
    """
    job.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
    job_start = time.time()
    log_scan_start(logger, job.target, ["<job>", f"{len(job.tasks)} task(s)"])

    for task in job.tasks:
        if task.status == TaskStatus.SKIPPED:
            continue

        task.status = TaskStatus.RUNNING
        task.start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        if progress_callback:
            progress_callback(job, task)

        task_start = time.time()
        try:
            if task.task_type == "banner_grab":
                _execute_banner_task(job.target, task)
            else:
                result = run_nmap_with_xml(job.target, task.args, timeout=task.timeout)
                task.command = " ".join(result.command)
                task.stdout = result.raw_output
                task.stderr = result.error_message
                if result.success:
                    task.status = TaskStatus.COMPLETED
                else:
                    task.status = TaskStatus.FAILED
                    log_warning(logger, f"{task.label} failed for {job.target}: {result.error_message}")

        except ScanTimeoutError as exc:
            task.status = TaskStatus.TIMEOUT
            task.stderr = str(exc)
            log_error(logger, f"{task.label} timed out for {job.target}: {exc}")

        except NmapNotFoundError as exc:
            task.status = TaskStatus.FAILED
            task.stderr = str(exc)
            log_error(logger, f"{task.label} could not run: {exc}")
            # Do NOT break out of the loop here: a banner-grab task later
            # in the job doesn't depend on Nmap at all and must still get
            # to run. Any later Nmap-based task will independently hit
            # this same NmapNotFoundError (a cheap shutil.which check) on
            # its own turn and be marked FAILED then — no need to
            # preemptively guess which tasks would fail.

        except KeyboardInterrupt:
            task.status = TaskStatus.FAILED
            task.stderr = "Interrupted by user."
            task.duration_seconds = time.time() - task_start
            task.end_time = time.strftime("%Y-%m-%d %H:%M:%S")
            if progress_callback:
                progress_callback(job, task)
            raise

        except Exception as exc:  # noqa: BLE001 - never let one task crash the whole job
            task.status = TaskStatus.FAILED
            task.stderr = f"Unexpected error: {exc}"
            log_error(logger, f"{task.label} raised an unexpected error: {exc}")

        task.duration_seconds = time.time() - task_start
        task.end_time = time.strftime("%Y-%m-%d %H:%M:%S")
        if progress_callback:
            progress_callback(job, task)

    job.duration_seconds = time.time() - job_start
    job.ended_at = time.strftime("%Y-%m-%d %H:%M:%S")
    log_scan_end(logger, job.target, job.duration_seconds)
    return job
