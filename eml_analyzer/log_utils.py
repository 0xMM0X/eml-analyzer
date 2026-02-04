"""Simple logging helper for verbose output."""

from __future__ import annotations

import sys
from datetime import datetime


def log(verbose: bool, message: str) -> None:
    if not verbose:
        return
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write(f"[{timestamp} UTC] {message}\n")


def log_debug(debug: bool, message: str) -> None:
    if not debug:
        return
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write(f"[{timestamp} UTC][DEBUG] {message}\n")
