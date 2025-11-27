# config.py
"""
Global paths and setup helpers for the Clinical Data Validator.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ARCHIVE_DIR = os.path.join(BASE_DIR, "Archive")
ERRORS_DIR = os.path.join(BASE_DIR, "Errors")
TEMP_DIR = os.path.join(BASE_DIR, "temp")

PROCESSED_LOG_PATH = os.path.join(BASE_DIR, "processed_files.log")


FTP_HOST = "127.0.0.1"  
FTP_USER = "kaungnyi"       
FTP_PASSWORD = ""              


def ensure_directories() -> None:
    """Create working directories if they don't exist."""
    for path in (ARCHIVE_DIR, ERRORS_DIR, TEMP_DIR):
        os.makedirs(path, exist_ok=True)
