"""Configuration helpers for EML Analyzer."""

import os
from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalyzerConfig:
    vt_api_key: str | None = None
    vt_timeout_seconds: int = 20
    max_bytes_for_hash: int | None = None
    allow_url_submission: bool = False
    abuseipdb_api_key: str | None = None
    urlscan_api_key: str | None = None
    hybrid_api_key: str | None = None
    mxtoolbox_api_key: str | None = None
    report_dark: bool = False
    report_score_details: bool = False

    @staticmethod
    def from_env() -> "AnalyzerConfig":
        _load_dotenv()
        return AnalyzerConfig(
            vt_api_key=os.getenv("VT_API_KEY"),
            vt_timeout_seconds=int(os.getenv("VT_TIMEOUT_SECONDS", "20")),
            max_bytes_for_hash=_parse_optional_int(os.getenv("MAX_BYTES_FOR_HASH")),
            allow_url_submission=os.getenv("VT_ALLOW_URL_SUBMISSION", "false").lower()
            in {"1", "true", "yes"},
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
            urlscan_api_key=os.getenv("URLSCAN_API_KEY"),
            hybrid_api_key=os.getenv("HYBRID_API_KEY"),
            mxtoolbox_api_key=os.getenv("MXTOOLBOX_API_KEY"),
            report_dark=os.getenv("REPORT_DARK", "false").lower() in {"1", "true", "yes"},
            report_score_details=os.getenv("REPORT_SCORE_DETAILS", "false").lower()
            in {"1", "true", "yes"},
        )


def _parse_optional_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _load_dotenv() -> None:
    env_path = Path(".env")
    if not env_path.exists():
        return
    try:
        content = env_path.read_text(encoding="utf-8")
    except OSError:
        return

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
