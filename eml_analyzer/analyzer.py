"""High-level analyzer orchestration."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any

from .abuseipdb_client import AbuseIpdbClient
from .cache import IocCache
from .config import AnalyzerConfig
from .ipinfo_client import IpInfoClient
from .url_screenshot import UrlScreenshotter
from .hybrid_analysis_client import HybridAnalysisClient
from .eml_parser import EmlParser
from .log_utils import log
from .mxtoolbox_client import MxToolboxClient
from .models import AnalysisReport, MessageAnalysis
from .opentip_client import OpenTipClient
from .redirect_utils import resolve_redirect_chain
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
        self._opentip_client = (
            OpenTipClient(api_key=config.opentip_api_key)
            if config.opentip_api_key
            else None
        )
        self._ipinfo_client = IpInfoClient(api_key=config.ipinfo_api_key)
        self._cache = None
        if config.ioc_cache_db:
            ttl_seconds = None
            if config.ioc_cache_ttl_hours:
                ttl_seconds = config.ioc_cache_ttl_hours * 3600
            self._cache = IocCache(config.ioc_cache_db, ttl_seconds=ttl_seconds)
        self._screenshotter = None
        if config.url_screenshot_enabled:
            self._screenshotter = UrlScreenshotter(
                timeout_ms=config.url_screenshot_timeout_ms
            )

    def analyze_path(
        self,
        path: str,
        extract_dir: str | None = None,
    ) -> AnalysisReport:
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
        if self._ipinfo_client:
            log(self._verbose, "Enriching IPs via GeoIP/ASN")
            self._enrich_geoip_recursive(root)
        if self._urlscan_client:
            log(self._verbose, "Submitting URLs to urlscan.io")
            self._enrich_urlscan_recursive(root)
        if self._config.url_redirect_resolve:
            log(self._verbose, "Resolving server-side URL redirects")
            self._resolve_redirects_recursive(root)
        if self._hybrid_client:
            log(self._verbose, "Enriching attachments via Hybrid Analysis")
            self._enrich_hybrid_recursive(root)
        if self._mxtoolbox_client:
            log(self._verbose, "Enriching sender domains via MxToolbox")
            self._enrich_domains_recursive(root)
        if self._opentip_client:
            log(self._verbose, "Enriching items via Kaspersky OpenTIP")
            self._enrich_opentip_recursive(root)
        if self._screenshotter:
            log(self._verbose, "Capturing URL screenshots")
            self._capture_url_screenshots_recursive(root)
        self._normalize_iocs_recursive(root)
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
            target = url.original_url or url.url
            if target not in seen:
                log(self._verbose, f"VT lookup for URL {target}")
                seen[target] = self._cached_lookup("vt_url", target, self._vt_client.get_url_report)
            url.vt = seen[target]

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
                seen[ip.ip] = self._cached_lookup("abuse_ip", ip.ip, self._abuse_client.check_ip)
            ip.abuseipdb = seen[ip.ip]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_ips_recursive(nested, seen)

    def _enrich_geoip_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._enrich_message_geoip_recursive(analysis, seen)

    def _enrich_message_geoip_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for ip in analysis.ips:
            if ip.ip not in seen:
                log(self._verbose, f"GeoIP lookup for IP {ip.ip}")
                seen[ip.ip] = self._cached_lookup("geoip_ip", ip.ip, self._ipinfo_client.lookup)
            ip.geoip = seen[ip.ip]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_geoip_recursive(nested, seen)

    def _enrich_urlscan_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._enrich_message_urlscan_recursive(analysis, seen)

    def _enrich_message_urlscan_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for url in analysis.urls:
            target = url.original_url or url.url
            if target not in seen:
                log(self._verbose, f"urlscan.io submit {target}")
                seen[target] = self._cached_lookup("urlscan_url", target, self._urlscan_client.scan_url)
            url.urlscan = seen[target]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_urlscan_recursive(nested, seen)

    def _resolve_redirects_recursive(self, analysis: MessageAnalysis) -> None:
        seen: dict[str, dict[str, Any]] = {}
        self._resolve_message_redirects_recursive(analysis, seen)

    def _resolve_message_redirects_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for url in analysis.urls:
            target = url.original_url or url.url
            if not target:
                continue
            if self._config.url_redirect_only_tracked:
                chain_info = url.redirect_chain or {}
                click_info = None
                if isinstance(chain_info, dict):
                    click_info = chain_info.get("click")
                if not (click_info and click_info.get("chain")):
                    continue
            if target not in seen:
                log(self._verbose, f"Resolve redirects for {target}")
                seen[target] = self._cached_lookup(
                    "redirect_url",
                    target,
                    lambda value: resolve_redirect_chain(
                        value,
                        timeout_seconds=self._config.url_redirect_timeout_seconds,
                        max_hops=self._config.url_redirect_max_hops,
                    ),
                )
            result = seen[target]
            if url.redirect_chain is None:
                url.redirect_chain = {}
            if isinstance(url.redirect_chain, dict):
                url.redirect_chain["server"] = result
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._resolve_message_redirects_recursive(nested, seen)

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
                seen[domain.domain] = self._cached_lookup("mx_domain", domain.domain, self._mxtoolbox_client.lookup_domain)
            domain.mxtoolbox = seen[domain.domain]
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_domains_recursive(nested, seen)

    def _enrich_opentip_recursive(self, analysis: MessageAnalysis) -> None:
        seen_urls: dict[str, dict[str, Any]] = {}
        seen_ips: dict[str, dict[str, Any]] = {}
        seen_domains: dict[str, dict[str, Any]] = {}
        seen_hashes: dict[str, dict[str, Any]] = {}
        self._enrich_message_opentip_recursive(
            analysis, seen_urls, seen_ips, seen_domains, seen_hashes
        )

    def _enrich_message_opentip_recursive(
        self,
        analysis: MessageAnalysis,
        seen_urls: dict[str, dict[str, Any]],
        seen_ips: dict[str, dict[str, Any]],
        seen_domains: dict[str, dict[str, Any]],
        seen_hashes: dict[str, dict[str, Any]],
    ) -> None:
        for url in analysis.urls:
            target = url.original_url or url.url
            if target not in seen_urls:
                log(self._verbose, f"OpenTIP lookup URL {target}")
                seen_urls[target] = self._cached_lookup("opentip_url", target, self._opentip_client.lookup_url)
            url.opentip = seen_urls[target]

        for ip in analysis.ips:
            if ip.ip not in seen_ips:
                log(self._verbose, f"OpenTIP lookup IP {ip.ip}")
                seen_ips[ip.ip] = self._cached_lookup("opentip_ip", ip.ip, self._opentip_client.lookup_ip)
            ip.opentip = seen_ips[ip.ip]

        for domain in analysis.domains:
            if domain.domain not in seen_domains:
                log(self._verbose, f"OpenTIP lookup domain {domain.domain}")
                seen_domains[domain.domain] = self._cached_lookup(
                    "opentip_domain",
                    domain.domain,
                    self._opentip_client.lookup_domain,
                )
            domain.opentip = seen_domains[domain.domain]

        for attachment in analysis.attachments:
            hash_value = attachment.sha256 or attachment.sha1 or attachment.md5
            if hash_value:
                if hash_value not in seen_hashes:
                    log(self._verbose, f"OpenTIP lookup hash {hash_value}")
                    seen_hashes[hash_value] = self._cached_lookup(
                        "opentip_hash",
                        hash_value,
                        self._opentip_client.lookup_hash,
                    )
                attachment.opentip = seen_hashes[hash_value]
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._enrich_message_opentip_recursive(
                    nested, seen_urls, seen_ips, seen_domains, seen_hashes
                )

    def _enrich_message_hybrid_recursive(
        self, analysis: MessageAnalysis, seen: dict[str, dict[str, Any]]
    ) -> None:
        for attachment in analysis.attachments:
            if not attachment.sha256 or not attachment.sha256.strip():
                continue
            if attachment.sha256 not in seen:
                log(self._verbose, f"Hybrid Analysis lookup {attachment.sha256.strip()}")
                seen[attachment.sha256] = self._cached_lookup(
                    "hybrid_hash",
                    attachment.sha256.strip(),
                    self._hybrid_client.lookup_hash,
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
        risk_score, risk_breakdown = _calculate_risk_score(
            analysis, urls, attachments, self._config
        )
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

    def _normalize_iocs_recursive(self, analysis: MessageAnalysis) -> None:
        self._normalize_message_iocs(analysis)
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._normalize_iocs_recursive(nested)

    def _normalize_message_iocs(self, analysis: MessageAnalysis) -> None:
        for url in analysis.urls:
            normalized = _normalize_url_ioc(url)
            url.normalized = normalized.get("sources")
            url.consensus = normalized.get("consensus")
        for ip in analysis.ips:
            normalized = _normalize_ip_ioc(ip)
            ip.normalized = normalized.get("sources")
            ip.consensus = normalized.get("consensus")
        for domain in analysis.domains:
            normalized = _normalize_domain_ioc(domain)
            domain.normalized = normalized.get("sources")
            domain.consensus = normalized.get("consensus")
        for attachment in analysis.attachments:
            normalized = _normalize_attachment_ioc(attachment)
            attachment.normalized = normalized.get("sources")
            attachment.consensus = normalized.get("consensus")

    def _capture_url_screenshots_recursive(self, analysis: MessageAnalysis) -> None:
        for url in analysis.urls:
            target = url.original_url or url.url
            if not target:
                continue
            result = self._screenshotter.capture(target)
            url.screenshot = result
        for attachment in analysis.attachments:
            nested = attachment.nested_eml
            if isinstance(nested, MessageAnalysis):
                self._capture_url_screenshots_recursive(nested)

    def _cached_lookup(self, ioc_type: str, value: str, fetcher) -> dict[str, Any]:
        if not self._cache:
            return fetcher(value)
        cached = self._cache.get(ioc_type, value)
        if cached is not None:
            return cached
        result = fetcher(value)
        self._cache.set(ioc_type, value, result)
        return result


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
    analysis: MessageAnalysis,
    urls: list[Any],
    attachments: list[Any],
    config: AnalyzerConfig,
) -> tuple[int, dict[str, Any]]:
    score = 0
    breakdown: dict[str, Any] = {
        "auth_failures": [],
        "auth_points": 0,
        "reply_to_mismatch": 0,
        "reply_to_points": 0,
        "vt_url": {"malicious": 0, "suspicious": 0},
        "vt_url_points": 0,
        "vt_files": {"malicious": 0, "suspicious": 0},
        "vt_files_points": 0,
        "urlscan": {"malicious": 0},
        "urlscan_points": 0,
        "hybrid": {"malicious": 0, "suspicious": 0},
        "hybrid_points": 0,
        "mx_failed": 0,
        "mx_points": 0,
        "executables": 0,
        "executables_points": 0,
        "abuseipdb": {"high": 0, "medium": 0, "low": 0},
        "abuse_points": 0,
        "arc_mismatch": 0,
        "arc_points": 0,
        "mta": {
            "received_time_inversion": 0,
            "date_after_first_received_over_60m": 0,
            "date_before_first_received_over_24h": 0,
            "no_received_headers": 0,
            "received_dates_unparsable": 0,
        },
        "mta_points": 0,
    }

    auth_results = analysis.headers.auth_results
    for key in ("spf", "dkim", "dmarc"):
        value = auth_results.get(key, "").lower()
        if "fail" in value or "softfail" in value:
            score += config.score_auth_fail
            breakdown["auth_failures"].append(key)
            breakdown["auth_points"] += config.score_auth_fail

    if _reply_to_from_mismatch(analysis):
        breakdown["reply_to_mismatch"] = 1
        breakdown["reply_to_points"] += config.score_reply_to_mismatch
        score += config.score_reply_to_mismatch

    for url in urls:
        vt_mal, vt_susp = _vt_counts(url.vt)
        if vt_mal:
            breakdown["vt_url"]["malicious"] += 1
        if vt_susp:
            breakdown["vt_url"]["suspicious"] += 1
        vt_score = _score_from_vt(
            url.vt,
            malicious_weight=config.score_vt_url_malicious,
            suspicious_weight=config.score_vt_url_suspicious,
        )
        breakdown["vt_url_points"] += vt_score
        score += vt_score

    for attachment in attachments:
        vt_mal, vt_susp = _vt_counts(attachment.vt)
        if vt_mal:
            breakdown["vt_files"]["malicious"] += 1
        if vt_susp:
            breakdown["vt_files"]["suspicious"] += 1
        vt_score = _score_from_vt(
            attachment.vt,
            malicious_weight=config.score_vt_file_malicious,
            suspicious_weight=config.score_vt_file_suspicious,
        )
        breakdown["vt_files_points"] += vt_score
        score += vt_score
        if _is_executable_attachment(attachment):
            score += config.score_executable
            breakdown["executables"] += 1
            breakdown["executables_points"] += config.score_executable

        hybrid_score = _score_from_hybrid(
            attachment.hybrid,
            malicious_weight=config.score_hybrid_malicious,
            suspicious_weight=config.score_hybrid_suspicious,
        )
        if hybrid_score:
            breakdown["hybrid_points"] += hybrid_score
            score += hybrid_score
            mal, susp = _hybrid_counts(attachment.hybrid)
            breakdown["hybrid"]["malicious"] += mal
            breakdown["hybrid"]["suspicious"] += susp

    ips = _collect_ips(analysis)
    for ip in ips:
        abuse_score = _score_from_abuse(
            ip.abuseipdb,
            config.score_abuse_high,
            config.score_abuse_medium,
            config.score_abuse_low,
        )
        if abuse_score >= 5:
            breakdown["abuseipdb"]["high"] += 1
        elif abuse_score >= 3:
            breakdown["abuseipdb"]["medium"] += 1
        elif abuse_score >= 1:
            breakdown["abuseipdb"]["low"] += 1
        breakdown["abuse_points"] += abuse_score
        score += abuse_score

    for url in urls:
        urlscan_score = _score_from_urlscan(url.urlscan, config.score_urlscan_malicious)
        if urlscan_score:
            breakdown["urlscan_points"] += urlscan_score
            score += urlscan_score
            breakdown["urlscan"]["malicious"] += 1

    arc_status = analysis.headers.arc_chain.get("status")
    if arc_status and arc_status != "ok":
        breakdown["arc_mismatch"] = 1
        breakdown["arc_points"] += config.score_arc_mismatch
        score += config.score_arc_mismatch

    mta_codes = set(analysis.headers.mta_anomalies or [])
    for code, weight in (
        ("received_time_inversion", config.score_mta_inversion),
        ("date_after_first_received_over_60m", config.score_mta_date_after_60m),
        ("date_before_first_received_over_24h", config.score_mta_date_before_24h),
        ("no_received_headers", config.score_no_received),
        ("received_dates_unparsable", config.score_received_unparsable),
    ):
        if code in mta_codes:
            breakdown["mta"][code] += 1
            breakdown["mta_points"] += weight
            score += weight

    for domain in analysis.domains:
        mx_failed = _mxtoolbox_failed_count(domain.mxtoolbox)
        if mx_failed:
            breakdown["mx_failed"] += mx_failed
            breakdown["mx_points"] += mx_failed * config.score_mx_failed
            score += mx_failed * config.score_mx_failed

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


def _reply_to_from_mismatch(analysis: MessageAnalysis) -> bool:
    from_addr = analysis.from_addr or ""
    reply_to = (analysis.headers.summary or {}).get("reply_to") or ""
    from_domain = _extract_email_domain(from_addr)
    reply_domain = _extract_email_domain(reply_to)
    if not from_domain or not reply_domain:
        return False
    return from_domain.lower() != reply_domain.lower()


def _extract_email_domain(value: str) -> str:
    if not value:
        return ""
    if "<" in value and ">" in value:
        value = value.split("<", 1)[-1].split(">", 1)[0]
    if "@" not in value:
        return ""
    return value.split("@", 1)[-1].strip()


def _score_from_abuse(
    abuse_result: dict[str, Any] | None, high: int, medium: int, low: int
) -> int:
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
        return high
    if confidence_value >= 50:
        return medium
    if confidence_value >= 25:
        return low
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


def _score_from_urlscan(urlscan: dict[str, Any] | None, weight: int) -> int:
    if not urlscan or urlscan.get("status") != "ok":
        return 0
    data = urlscan.get("data") or {}
    verdicts = data.get("verdicts", {})
    overall = verdicts.get("overall", {})
    malicious = overall.get("malicious")
    if malicious is True:
        return weight
    return 0


def _score_from_hybrid(
    hybrid: dict[str, Any] | None, malicious_weight: int, suspicious_weight: int
) -> int:
    if not hybrid or hybrid.get("status") != "ok":
        return 0
    data = hybrid.get("data")
    if not isinstance(data, list) or not data:
        return 0
    score = 0
    for item in data:
        verdict = str(item.get("verdict", "")).lower()
        if verdict == "malicious":
            score += malicious_weight
        elif verdict == "suspicious":
            score += suspicious_weight
    return score


def _hybrid_counts(hybrid: dict[str, Any] | None) -> tuple[int, int]:
    if not hybrid or hybrid.get("status") != "ok":
        return (0, 0)
    data = hybrid.get("data")
    if not isinstance(data, list) or not data:
        return (0, 0)
    mal = 0
    susp = 0
    for item in data:
        verdict = str(item.get("verdict", "")).lower()
        if verdict == "malicious":
            mal += 1
        elif verdict == "suspicious":
            susp += 1
    return (mal, susp)


def _mxtoolbox_failed_count(mx: dict[str, Any] | None) -> int:
    if not mx or mx.get("status") != "ok":
        return 0
    data = mx.get("data")
    if isinstance(data, list) and data:
        data = data[0]
    if not isinstance(data, dict):
        return 0
    failed = data.get("Failed") or data.get("failed") or []
    if isinstance(failed, list):
        return len(failed)
    return 0


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




def _normalize_url_ioc(url: Any) -> dict[str, Any]:
    sources = []
    if url.vt:
        sources.append(_normalize_vt(url.vt, "virustotal"))
    if url.urlscan:
        sources.append(_normalize_urlscan(url.urlscan))
    if url.opentip:
        sources.append(_normalize_opentip(url.opentip))
    consensus = _consensus(sources)
    return {"sources": sources, "consensus": consensus}


def _normalize_ip_ioc(ip: Any) -> dict[str, Any]:
    sources = []
    if ip.abuseipdb:
        sources.append(_normalize_abuse(ip.abuseipdb))
    if ip.opentip:
        sources.append(_normalize_opentip(ip.opentip))
    consensus = _consensus(sources)
    return {"sources": sources, "consensus": consensus}


def _normalize_domain_ioc(domain: Any) -> dict[str, Any]:
    sources = []
    if domain.opentip:
        sources.append(_normalize_opentip(domain.opentip))
    consensus = _consensus(sources)
    return {"sources": sources, "consensus": consensus}


def _normalize_attachment_ioc(attachment: Any) -> dict[str, Any]:
    sources = []
    if attachment.vt:
        sources.append(_normalize_vt(attachment.vt, "virustotal"))
    if attachment.hybrid:
        sources.append(_normalize_hybrid(attachment.hybrid))
    if attachment.opentip:
        sources.append(_normalize_opentip(attachment.opentip))
    consensus = _consensus(sources)
    return {"sources": sources, "consensus": consensus}


def _normalize_vt(vt: dict[str, Any], source: str) -> dict[str, Any]:
    if not vt or vt.get("status") != "ok":
        return {"source": source, "verdict": "unknown"}
    data = vt.get("data") or {}
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif harmless > 0:
        verdict = "clean"
    else:
        verdict = "unknown"
    return {"source": source, "verdict": verdict, "malicious": malicious, "suspicious": suspicious}


def _normalize_urlscan(urlscan: dict[str, Any]) -> dict[str, Any]:
    if not urlscan or urlscan.get("status") != "ok":
        return {"source": "urlscan", "verdict": "unknown"}
    data = urlscan.get("data") or {}
    verdicts = data.get("verdicts", {}) or {}
    overall = verdicts.get("overall", {}) or {}
    if overall.get("malicious") is True:
        return {"source": "urlscan", "verdict": "malicious"}
    if overall.get("score", 0) >= 50:
        return {"source": "urlscan", "verdict": "suspicious"}
    return {"source": "urlscan", "verdict": "clean"}


def _normalize_hybrid(hybrid: dict[str, Any]) -> dict[str, Any]:
    if not hybrid or hybrid.get("status") != "ok":
        return {"source": "hybrid", "verdict": "unknown"}
    data = hybrid.get("data")
    verdicts = []
    if isinstance(data, list):
        for item in data:
            verdict = str(item.get("verdict", "")).lower()
            if verdict:
                verdicts.append(verdict)
    if "malicious" in verdicts:
        return {"source": "hybrid", "verdict": "malicious"}
    if "suspicious" in verdicts:
        return {"source": "hybrid", "verdict": "suspicious"}
    if verdicts:
        return {"source": "hybrid", "verdict": "clean"}
    return {"source": "hybrid", "verdict": "unknown"}


def _normalize_opentip(opentip: dict[str, Any]) -> dict[str, Any]:
    if not opentip or opentip.get("status") != "ok":
        return {"source": "opentip", "verdict": "unknown"}
    data = opentip.get("data") or {}
    zone = str(data.get("Zone") or data.get("zone") or "").lower()
    mapping = {
        "red": "malicious",
        "orange": "suspicious",
        "yellow": "unknown",
        "grey": "unknown",
        "gray": "unknown",
        "green": "clean",
    }
    verdict = mapping.get(zone, "unknown")
    return {"source": "opentip", "verdict": verdict, "zone": zone}


def _normalize_abuse(abuse: dict[str, Any]) -> dict[str, Any]:
    if not abuse or abuse.get("status") != "ok":
        return {"source": "abuseipdb", "verdict": "unknown"}
    data = (abuse.get("data") or {}).get("data", {})
    confidence = data.get("abuseConfidenceScore")
    try:
        score = int(confidence)
    except (TypeError, ValueError):
        score = 0
    if score >= 80:
        verdict = "malicious"
    elif score >= 50:
        verdict = "suspicious"
    elif score == 0:
        verdict = "clean"
    else:
        verdict = "unknown"
    return {"source": "abuseipdb", "verdict": verdict, "confidence": score}


def _consensus(sources: list[dict[str, Any]]) -> dict[str, Any]:
    if not sources:
        return {"verdict": "unknown", "score": 0, "sources": []}
    scores = {"malicious": 3, "suspicious": 2, "clean": 0, "unknown": 1}
    total = 0
    votes = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    for src in sources:
        verdict = src.get("verdict", "unknown")
        votes[verdict] = votes.get(verdict, 0) + 1
        total += scores.get(verdict, 1)
    avg = total / max(len(sources), 1)
    if avg >= 2.5:
        verdict = "malicious"
    elif avg >= 1.6:
        verdict = "suspicious"
    elif votes.get("clean", 0) == len(sources):
        verdict = "clean"
    else:
        verdict = "unknown"
    top_source = _top_source(sources)
    return {"verdict": verdict, "score": round(avg, 2), "votes": votes, "top_source": top_source}


def _top_source(sources: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not sources:
        return None
    priority = {"malicious": 4, "suspicious": 3, "clean": 2, "unknown": 1}
    best = None
    best_score = -1
    for src in sources:
        verdict = src.get("verdict", "unknown")
        score = priority.get(verdict, 0)
        if score > best_score:
            best = src
            best_score = score
    return best
