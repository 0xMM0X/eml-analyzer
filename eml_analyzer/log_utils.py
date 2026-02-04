"""Simple logging helper for verbose output."""

from __future__ import annotations

import sys
from datetime import datetime


def log(verbose: bool, message: str) -> None:
    if not verbose:
        return
    _write_line(f"[{_ts()} UTC] {message}\n")


def log_debug(debug: bool, message: str) -> None:
    if not debug:
        return
    _write_line(f"[{_ts()} UTC][DEBUG] {message}\n")


def set_log_file(path: str | None) -> None:
    global _LOG_FILE
    _LOG_FILE = path


def _ts() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _write_line(line: str) -> None:
    if _LOG_FILE:
        with open(_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    else:
        sys.stderr.write(line)


_LOG_FILE: str | None = None
