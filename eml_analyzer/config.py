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
    opentip_api_key: str | None = None
    report_dark: bool = False
    report_score_details: bool = False
    report_theme_file: str | None = None
    ioc_cache_db: str | None = None
    ioc_cache_ttl_hours: int | None = None
    report_defang_urls: bool = False
    verbose: bool = False
    debug: bool = False
    debug_log_file: str | None = None
    ipinfo_api_key: str | None = None
    url_screenshot_enabled: bool = False
    url_screenshot_timeout_ms: int = 20000
    url_redirect_resolve: bool = False
    url_redirect_max_hops: int = 5
    url_redirect_timeout_seconds: int = 10
    url_redirect_only_tracked: bool = False
    score_auth_fail: int = 2
    score_vt_url_malicious: int = 5
    score_vt_url_suspicious: int = 3
    score_vt_file_malicious: int = 6
    score_vt_file_suspicious: int = 3
    score_executable: int = 1
    score_abuse_high: int = 5
    score_abuse_medium: int = 3
    score_abuse_low: int = 1
    score_arc_mismatch: int = 2
    score_mta_inversion: int = 2
    score_mta_date_after_60m: int = 1
    score_mta_date_before_24h: int = 2
    score_no_received: int = 1
    score_received_unparsable: int = 1
    score_urlscan_malicious: int = 3
    score_hybrid_malicious: int = 4
    score_hybrid_suspicious: int = 2
    score_mx_failed: int = 1
    score_reply_to_mismatch: int = 2

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
            opentip_api_key=os.getenv("OPENTIP_API_KEY"),
            report_dark=os.getenv("REPORT_DARK", "false").lower() in {"1", "true", "yes"},
            report_score_details=os.getenv("REPORT_SCORE_DETAILS", "false").lower()
            in {"1", "true", "yes"},
            report_theme_file=os.getenv("REPORT_THEME_FILE"),
            ioc_cache_db=os.getenv("IOC_CACHE_DB"),
            ioc_cache_ttl_hours=_parse_optional_int(os.getenv("IOC_CACHE_TTL_HOURS")),
            report_defang_urls=os.getenv("REPORT_DEFANG_URLS", "false").lower()
            in {"1", "true", "yes"},
            verbose=os.getenv("VERBOSE", "false").lower() in {"1", "true", "yes"},
            debug=os.getenv("DEBUG", "false").lower() in {"1", "true", "yes"},
            debug_log_file=os.getenv("DEBUG_LOG_FILE"),
            ipinfo_api_key=os.getenv("IPINFO_API_KEY"),
            url_screenshot_enabled=os.getenv("URL_SCREENSHOT_ENABLED", "false").lower()
            in {"1", "true", "yes"},
            url_screenshot_timeout_ms=_parse_int(
                os.getenv("URL_SCREENSHOT_TIMEOUT_MS"), 20000
            ),
            url_redirect_resolve=os.getenv("URL_REDIRECT_RESOLVE", "false").lower()
            in {"1", "true", "yes"},
            url_redirect_max_hops=_parse_int(os.getenv("URL_REDIRECT_MAX_HOPS"), 5),
            url_redirect_timeout_seconds=_parse_int(
                os.getenv("URL_REDIRECT_TIMEOUT_SECONDS"), 10
            ),
            url_redirect_only_tracked=os.getenv("URL_REDIRECT_ONLY_TRACKED", "false").lower()
            in {"1", "true", "yes"},
            score_auth_fail=_parse_int(os.getenv("SCORE_AUTH_FAIL"), 2),
            score_vt_url_malicious=_parse_int(os.getenv("SCORE_VT_URL_MALICIOUS"), 5),
            score_vt_url_suspicious=_parse_int(os.getenv("SCORE_VT_URL_SUSPICIOUS"), 3),
            score_vt_file_malicious=_parse_int(os.getenv("SCORE_VT_FILE_MALICIOUS"), 6),
            score_vt_file_suspicious=_parse_int(os.getenv("SCORE_VT_FILE_SUSPICIOUS"), 3),
            score_executable=_parse_int(os.getenv("SCORE_EXECUTABLE"), 1),
            score_abuse_high=_parse_int(os.getenv("SCORE_ABUSE_HIGH"), 5),
            score_abuse_medium=_parse_int(os.getenv("SCORE_ABUSE_MEDIUM"), 3),
            score_abuse_low=_parse_int(os.getenv("SCORE_ABUSE_LOW"), 1),
            score_arc_mismatch=_parse_int(os.getenv("SCORE_ARC_MISMATCH"), 2),
            score_mta_inversion=_parse_int(os.getenv("SCORE_MTA_INVERSION"), 2),
            score_mta_date_after_60m=_parse_int(os.getenv("SCORE_MTA_DATE_AFTER_60M"), 1),
            score_mta_date_before_24h=_parse_int(os.getenv("SCORE_MTA_DATE_BEFORE_24H"), 2),
            score_no_received=_parse_int(os.getenv("SCORE_NO_RECEIVED_HEADERS"), 1),
            score_received_unparsable=_parse_int(os.getenv("SCORE_RECEIVED_UNPARSABLE"), 1),
            score_urlscan_malicious=_parse_int(os.getenv("SCORE_URLSCAN_MALICIOUS"), 3),
            score_hybrid_malicious=_parse_int(os.getenv("SCORE_HYBRID_MALICIOUS"), 4),
            score_hybrid_suspicious=_parse_int(os.getenv("SCORE_HYBRID_SUSPICIOUS"), 2),
            score_mx_failed=_parse_int(os.getenv("SCORE_MX_FAILED"), 1),
            score_reply_to_mismatch=_parse_int(os.getenv("SCORE_REPLY_TO_MISMATCH"), 2),
        )


def _parse_optional_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _parse_int(raw: str | None, default: int) -> int:
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


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
