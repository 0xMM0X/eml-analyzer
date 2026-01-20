"""High-level analyzer orchestration."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any

from .abuseipdb_client import AbuseIpdbClient
from .config import AnalyzerConfig
from .hybrid_analysis_client import HybridAnalysisClient
from .eml_parser import EmlParser
from .log_utils import log
from .mxtoolbox_client import MxToolboxClient
from .models import AnalysisReport, MessageAnalysis
from .urlscan_client import UrlscanClient
from .virustotal_client import VirusTotalClient


class EmlAnalyzer:
    def __init__(self, config: AnalyzerConfig, verbose: bool = False) -> None:
        self._config = config
        self._verbose = verbose
        self._vt_client = (
            VirusTotalClient(
                api_key=config.vt_api_key,
                timeout_seconds=config.vt_timeout_seconds,
                allow_url_submission=config.allow_url_submission,
            )
            if config.vt_api_key
            else None
        )
        self._abuse_client = (
            AbuseIpdbClient(api_key=config.abuseipdb_api_key)
            if config.abuseipdb_api_key
            else None
        )
        self._urlscan_client = (
            UrlscanClient(api_key=config.urlscan_api_key)
            if config.urlscan_api_key
            else None
        )
        self._hybrid_client = (
            HybridAnalysisClient(api_key=config.hybrid_api_key)
            if config.hybrid_api_key
            else None
        )
        self._mxtoolbox_client = (
            MxToolboxClient(api_key=config.mxtoolbox_api_key)
            if config.mxtoolbox_api_key
            else None
        )

    def analyze_path(self, path: str, extract_dir: str | None = None) -> AnalysisReport:
        log(self._verbose, f"Reading EML from {path}")
        with open(path, "rb") as handle:
            data = handle.read()
        parser = EmlParser(
            vt_client=self._vt_client,
            max_bytes_for_hash=self._config.max_bytes_for_hash,
            extract_dir=extract_dir,
            verbose=self._verbose,
        )
        root = parser.parse_bytes(data)
        if self._vt_client:
            log(self._verbose, "Enriching URLs via VirusTotal")
            self._enrich_urls_recursive(root)
        if self._abuse_client:
            log(self._verbose, "Enriching IPs via AbuseIPDB")
            self._enrich_ips_recursive(root)
        if self._urlscan_client:
            log(self._verbose, "Submitting URLs to urlscan.io")
            self._enrich_urlscan_recursive(root)
        if self._hybrid_client:
            log(self._verbose, "Enriching attachments via Hybrid Analysis")
            self._enrich_hybrid_recursive(root)
        if self._mxtoolbox_client:
            log(self._verbose, "Enriching sender domains via MxToolbox")
            self._enrich_domains_recursive(root)
        statistics = self._build_statistics(root)
        return AnalysisReport(root=root, statistics=statistics)

    def report_as_dict(self, report: AnalysisReport) -> dict[str, Any]:
        return {
            "root": _message_to_dict(report.root),
            "statistics": report.statistics,
        }

    def _enrich_urls_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._enrich_message_urls_recursive(analysis, seen)

    def _enrich_message_urls_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for url in analysis.urls:
            if url.url not in seen:
                log(self._verbose, f"VT lookup for URL {url.url}")
                seen[url.url] = self._vt_client.get_url_report(url.url)
            url.vt = seen[url.url]

        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_urls_recursive(nested, seen)

    def _enrich_ips_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._enrich_message_ips_recursive(analysis, seen)

    def _enrich_message_ips_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for ip in analysis.ips:
            if ip.ip not in seen:
                log(self._verbose, f"AbuseIPDB lookup for IP {ip.ip}")
                seen[ip.ip] = self._abuse_client.check_ip(ip.ip)
            ip.abuseipdb = seen[ip.ip]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_ips_recursive(nested, seen)

    def _enrich_urlscan_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._enrich_message_urlscan_recursive(analysis, seen)

    def _enrich_message_urlscan_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for url in analysis.urls:
            if url.url not in seen:
                log(self._verbose, f"urlscan.io submit {url.url}")
                seen[url.url] = self._urlscan_client.scan_url(url.url)
            url.urlscan = seen[url.url]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_urlscan_recursive(nested, seen)

    def _enrich_hybrid_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._enrich_message_hybrid_recursive(analysis, seen)

    def _enrich_domains_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._enrich_message_domains_recursive(analysis, seen)

    def _enrich_message_domains_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for domain in analysis.domains:
            if domain.domain not in seen:
                log(self._verbose, f"MxToolbox lookup for domain {domain.domain}")
                seen[domain.domain] = self._mxtoolbox_client.lookup_domain(domain.domain)
            domain.mxtoolbox = seen[domain.domain]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_domains_recursive(nested, seen)

    def _enrich_message_hybrid_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for attachment in analysis.attachments:
            if not attachment.sha256 or not attachment.sha256.strip():
                continue
            if attachment.sha256 not in seen:
                log(self._verbose, f"Hybrid Analysis lookup {attachment.sha256.strip()}")
                seen[attachment.sha256] = self._hybrid_client.lookup_hash(
                    attachment.sha256.strip()
                )
            attachment.hybrid = seen[attachment.sha256]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_hybrid_recursive(nested, seen)

    def _build_statistics(self, analysis: MessageAnalysis) -> dict[str, Any]:
        urls = _collect_urls(analysis)
        attachments = _collect_attachments(analysis)
        ips = _collect_ips(analysis)
        url_count = len(urls)
        attachment_count = len(attachments)
        ip_count = len(ips)
        unique_ips = len({item.ip for item in ips})
        hash_counts = Counter([item.sha256 for item in attachments if item.sha256])
        risk_score, risk_breakdown = _calculate_risk_score(analysis, urls, attachments)
        risk_level = _risk_level_from_score(risk_score)

        return {
            "url_count": url_count,
            "attachment_count": attachment_count,
            "ip_count": ip_count,
            "unique_ip_count": unique_ips,
            "unique_attachment_hashes": len(hash_counts),
            "attachment_hashes": dict(hash_counts),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_breakdown": risk_breakdown,
        }


def _message_to_dict(message: MessageAnalysis) -> dict[str, Any]:
    data = asdict(message)
    return data


def _collect_urls(analysis: MessageAnalysis) -> list[Any]:
    urls = list(analysis.urls)
    for attachment in analysis.attachments:
        nested = attachment.nested_eml
        if isinstance(nested, MessageAnalysis):
            urls.extend(_collect_urls(nested))
    return urls


def _collect_attachments(analysis: MessageAnalysis) -> list[Any]:
    attachments = list(analysis.attachments)
    for attachment in analysis.attachments:
        nested = attachment.nested_eml
        if isinstance(nested, MessageAnalysis):
            attachments.extend(_collect_attachments(nested))
    return attachments


def _collect_ips(analysis: MessageAnalysis) -> list[Any]:
    ips = list(analysis.ips)
    for attachment in analysis.attachments:
        nested = attachment.nested_eml
        if isinstance(nested, MessageAnalysis):
            ips.extend(_collect_ips(nested))
    return ips


def _calculate_risk_score(
    analysis: MessageAnalysis, urls: list[Any], attachments: list[Any]
) -> tuple[int, dict[str, Any]]:
    score = 0
    breakdown: dict[str, Any] = {
        "auth_failures": [],
        "auth_points": 0,
        "vt_url": {"malicious": 0, "suspicious": 0},
        "vt_url_points": 0,
        "vt_files": {"malicious": 0, "suspicious": 0},
        "vt_files_points": 0,
        "executables": 0,
        "executables_points": 0,
        "abuseipdb": {"high": 0, "medium": 0, "low": 0},
        "abuse_points": 0,
    }

    auth_results = analysis.headers.auth_results
    for key in ("spf", "dkim", "dmarc"):
        value = auth_results.get(key, "").lower()
        if "fail" in value or "softfail" in value:
            score += 2
            breakdown["auth_failures"].append(key)
            breakdown["auth_points"] += 2

    for url in urls:
        vt_mal, vt_susp = _vt_counts(url.vt)
        if vt_mal:
            breakdown["vt_url"]["malicious"] += 1
        if vt_susp:
            breakdown["vt_url"]["suspicious"] += 1
        vt_score = _score_from_vt(url.vt, malicious_weight=5, suspicious_weight=3)
        breakdown["vt_url_points"] += vt_score
        score += vt_score

    for attachment in attachments:
        vt_mal, vt_susp = _vt_counts(attachment.vt)
        if vt_mal:
            breakdown["vt_files"]["malicious"] += 1
        if vt_susp:
            breakdown["vt_files"]["suspicious"] += 1
        vt_score = _score_from_vt(attachment.vt, malicious_weight=6, suspicious_weight=3)
        breakdown["vt_files_points"] += vt_score
        score += vt_score
        if _is_executable_attachment(attachment):
            score += 1
            breakdown["executables"] += 1
            breakdown["executables_points"] += 1

    ips = _collect_ips(analysis)
    for ip in ips:
        abuse_score = _score_from_abuse(ip.abuseipdb)
        if abuse_score >= 5:
            breakdown["abuseipdb"]["high"] += 1
        elif abuse_score >= 3:
            breakdown["abuseipdb"]["medium"] += 1
        elif abuse_score >= 1:
            breakdown["abuseipdb"]["low"] += 1
        breakdown["abuse_points"] += abuse_score
        score += abuse_score

    breakdown["total_before_cap"] = score
    if score > 10:
        score = 10
    return score, breakdown


def _score_from_vt(
    vt_result: dict[str, Any] | None, malicious_weight: int, suspicious_weight: int
) -> int:
    if not vt_result or vt_result.get("status") != "ok":
        return 0
    data = vt_result.get("data") or {}
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    score = 0
    if malicious > 0:
        score += malicious_weight
    if suspicious > 0:
        score += suspicious_weight
    return score


def _score_from_abuse(abuse_result: dict[str, Any] | None) -> int:
    if not abuse_result or abuse_result.get("status") != "ok":
        return 0
    data = (abuse_result.get("data") or {}).get("data", {})
    confidence = data.get("abuseConfidenceScore")
    if confidence is None:
        return 0
    try:
        confidence_value = int(confidence)
    except (TypeError, ValueError):
        return 0
    if confidence_value >= 80:
        return 5
    if confidence_value >= 50:
        return 3
    if confidence_value >= 25:
        return 1
    return 0


def _vt_counts(vt_result: dict[str, Any] | None) -> tuple[int, int]:
    if not vt_result or vt_result.get("status") != "ok":
        return 0, 0
    data = vt_result.get("data") or {}
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    return (1 if malicious > 0 else 0, 1 if suspicious > 0 else 0)


def _is_executable_attachment(attachment: Any) -> bool:
    filename = (attachment.filename or "").lower()
    return filename.endswith(
        (
            ".exe",
            ".dll",
            ".bat",
            ".cmd",
            ".js",
            ".vbs",
            ".ps1",
            ".scr",
            ".jar",
            ".msi",
        )
    )


def _risk_level_from_score(score: int) -> str:
    if score < 5:
        return "clear"
    if score > 5:
        return "high"
    return "medium"
