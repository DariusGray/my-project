# logger.py
"""
Error logging and processed-files tracking.
Each error log entry:
    ISO8601 timestamp | UUID4 | filename | error message
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Iterable

from config import PROCESSED_LOG_PATH


def _get_error_report_path(errors_dir: str) -> str:
    """Return full path to error_report.log inside the given Errors directory."""
    return os.path.join(errors_dir, "error_report.log")


def log_error(filename: str, message: str, errors_dir: str) -> None:
    """
    Append a single error entry to error_report.log inside the given Errors directory.
    """
    timestamp = datetime.now().isoformat()
    guid = str(uuid.uuid4())
    error_report_path = _get_error_report_path(errors_dir)

    os.makedirs(os.path.dirname(error_report_path), exist_ok=True)

    line = f"{timestamp} | {guid} | {filename} | {message}\n"
    with open(error_report_path, "a", encoding="utf-8") as f:
        f.write(line)


def log_errors(filename: str, messages: Iterable[str], errors_dir: str) -> None:
    """
    Convenience function to log multiple error messages for one file.
    """
    for msg in messages:
        log_error(filename, msg, errors_dir)


def has_been_processed(filename: str) -> bool:
    """
    Check if filename has already been processed (file-level duplicate prevention).
    """
    if not os.path.exists(PROCESSED_LOG_PATH):
        return False

    with open(PROCESSED_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip() == filename:
                return True
    return False


def mark_processed(filename: str) -> None:
    """
    Append filename to processed_files.log.
    """
    with open(PROCESSED_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(filename + "\n")
