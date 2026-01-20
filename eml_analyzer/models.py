"""Data models for analysis results."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttachmentInfo:
    filename: str | None
    content_type: str
    size: int
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    vt: dict[str, Any] | None = None
    hybrid: dict[str, Any] | None = None
    is_eml: bool = False
    nested_eml: Any | None = None
    saved_path: str | None = None
    office_info: dict[str, Any] | None = None


@dataclass
class UrlInfo:
    url: str
    source: str
    vt: dict[str, Any] | None = None
    urlscan: dict[str, Any] | None = None


@dataclass
class DomainInfo:
    domain: str
    mxtoolbox: dict[str, Any] | None = None


@dataclass
class IpInfo:
    ip: str
    source: str
    abuseipdb: dict[str, Any] | None = None


@dataclass
class HeaderAnalysis:
    summary: dict[str, Any] = field(default_factory=dict)
    received_chain: list[str] = field(default_factory=list)
    auth_results: dict[str, str] = field(default_factory=dict)
    arc_chain: dict[str, Any] = field(default_factory=dict)
    timing: dict[str, Any] = field(default_factory=dict)
    mta_anomalies: list[str] = field(default_factory=list)
    mta_anomaly_details: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class MessageAnalysis:
    message_id: str | None
    subject: str | None
    from_addr: str | None
    to_addrs: list[str]
    date: str | None
    headers: HeaderAnalysis
    urls: list[UrlInfo] = field(default_factory=list)
    ips: list[IpInfo] = field(default_factory=list)
    domains: list[DomainInfo] = field(default_factory=list)
    mime_tree: dict[str, Any] | None = None
    attachments: list[AttachmentInfo] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    root: MessageAnalysis
    statistics: dict[str, Any] = field(default_factory=dict)
