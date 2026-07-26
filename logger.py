"""
logger.py
==========
Central logging configuration for ReconMaster. Writes a daily rotating
log file into logs/ containing timestamps, executed commands, durations,
warnings, and errors.
"""

from __future__ import annotations

import logging
from datetime import datetime

from config import LOGS_DIR


def get_logger(name: str = "reconmaster") -> logging.Logger:
    """
    Return a configured logger that writes to logs/reconmaster_<date>.log
    and also echoes warnings/errors to the console.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        # Already configured (avoid duplicate handlers on repeated calls)
        return logger

    logger.setLevel(logging.DEBUG)

    log_file = LOGS_DIR / f"reconmaster_{datetime.now().strftime('%Y_%m_%d')}.log"

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(file_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def log_scan_start(logger: logging.Logger, target: str, command: list[str]) -> None:
    logger.info(f"Scan started | target={target} | command={' '.join(command)}")


def log_scan_end(logger: logging.Logger, target: str, duration: float) -> None:
    logger.info(f"Scan completed | target={target} | duration={duration:.2f}s")


def log_error(logger: logging.Logger, message: str) -> None:
    logger.error(message)


def log_warning(logger: logging.Logger, message: str) -> None:
    logger.warning(message)


def log_program_start(logger: logging.Logger, version: str) -> None:
    logger.info(f"ReconMaster v{version} starting")


def log_program_exit(logger: logging.Logger, exit_code: int) -> None:
    logger.info(f"ReconMaster exiting | exit_code={exit_code}")


def log_job_start(
    logger: logging.Logger,
    target: str,
    task_keys: list[str],
    timeout_mode: str,
    nse_scripts: list[str] | None = None,
    firewall_techniques: list[str] | None = None,
) -> None:
    """Log the full configuration of a multi-task scan job before it runs."""
    logger.info(
        "Job started | target=%s | tasks=%s | timeout_mode=%s | nse=%s | firewall=%s",
        target, ",".join(task_keys), timeout_mode,
        ",".join(nse_scripts or []) or "-",
        ",".join(firewall_techniques or []) or "-",
    )


def log_report_generated(logger: logging.Logger, fmt: str, path: str) -> None:
    logger.info(f"Report generated | format={fmt} | path={path}")
