"""EML parsing and analysis."""

from __future__ import annotations

import email
import os
import re
import mimetypes
from email import policy
from email.message import Message
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from datetime import timezone
from typing import Any

from .hashing import hash_bytes
from .log_utils import log
from .office_utils import analyze_office_attachment
from .pdf_utils import analyze_pdf_attachment
from .ip_utils import extract_ips_from_text
from .models import AttachmentInfo, DomainInfo, HeaderAnalysis, IpInfo, MessageAnalysis, UrlInfo
from .url_utils import extract_urls_from_html, extract_urls_from_text, detect_rewritten_url, extract_anchor_pairs
from .virustotal_client import VirusTotalClient


class EmlParser:
    def __init__(
        self,
        vt_client: VirusTotalClient | None = None,
        max_bytes_for_hash: int | None = None,
        max_depth: int = 5,
        extract_dir: str | None = None,
        verbose: bool = False,
    ) -> None:
        self._vt_client = vt_client
        self._max_bytes_for_hash = max_bytes_for_hash
        self._max_depth = max_depth
        self._extract_dir = extract_dir
        self._attachment_index = 0
        self._verbose = verbose

    def parse_bytes(self, data: bytes, depth: int = 0) -> MessageAnalysis:
        log(self._verbose, f"Parsing EML bytes (depth={depth}, size={len(data)})")
        msg = email.message_from_bytes(data, policy=policy.default)
        return self._parse_message(msg, depth)

    def _parse_message(self, msg: Message, depth: int) -> MessageAnalysis:
        headers = self._analyze_headers(msg)
        raw_headers = {k: v for k, v in msg.items()}

        analysis = MessageAnalysis(
            message_id=msg.get("Message-Id"),
            subject=msg.get("Subject"),
            from_addr=msg.get("From"),
            to_addrs=self._split_addresses(msg.get_all("To", [])),
            date=msg.get("Date"),
            headers=headers,
            raw_headers=raw_headers,
        )
        analysis.mime_tree = _build_mime_tree(msg)
        self._extract_sender_domain(analysis)
        self._extract_ips_from_headers(headers, analysis)

        for part in msg.walk():
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            log(self._verbose, f"Part content_type={content_type} disposition={disposition}")

            if content_type in {"text/plain", "text/html"}:
                self._extract_urls_from_part(part, analysis)
                self._extract_ips_from_part(part, analysis)

            if disposition in {"attachment", "inline"} or part.get_filename():
                attachment = self._handle_attachment(part, depth)
                analysis.attachments.append(attachment)

        return analysis

    def _handle_attachment(self, part: Message, depth: int) -> AttachmentInfo:
        filename = part.get_filename()
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        size = len(payload)
        log(self._verbose, f"Attachment: {filename} type={content_type} size={size}")

        hash_payload = payload
        if self._max_bytes_for_hash is not None:
            hash_payload = payload[: self._max_bytes_for_hash]

        hash_result = hash_bytes(hash_payload) if payload else None
        attachment = AttachmentInfo(
            filename=filename,
            content_type=content_type,
            size=size,
            md5=hash_result.md5 if hash_result else None,
            sha1=hash_result.sha1 if hash_result else None,
            sha256=hash_result.sha256 if hash_result else None,
            is_eml=self._is_eml_attachment(part, filename),
        )

        attachment.office_info = analyze_office_attachment(filename, payload)
        if attachment.office_info:
            log(self._verbose, f"Office analysis: {attachment.office_info}")
        attachment.header_check = _check_attachment_header(filename, content_type, payload)
        attachment.pdf_info = analyze_pdf_attachment(filename, payload)
        if attachment.pdf_info:
            log(self._verbose, f"PDF analysis: {attachment.pdf_info}")
        attachment.password_protected = _detect_password_protection(filename, payload)
        attachment.entropy = _compute_entropy(payload)

        if self._extract_dir and payload:
            saved_path = self._write_attachment(payload, filename, content_type, depth)
            attachment.saved_path = saved_path
            log(self._verbose, f"Saved attachment to {saved_path}")

        if self._vt_client and attachment.sha256:
            log(self._verbose, f"VT lookup for attachment {attachment.sha256}")
            attachment.vt = self._vt_client.get_file_report(attachment.sha256)

        if attachment.is_eml and depth < self._max_depth:
            log(self._verbose, f"Parsing nested EML (depth={depth + 1})")
            nested = self._parse_nested_eml(part, payload, depth)
            attachment.nested_eml = nested

        return attachment

    def _extract_urls_from_part(self, part: Message, analysis: MessageAnalysis) -> None:
        content_type = part.get_content_type()
        try:
            text = part.get_content()
        except (LookupError, UnicodeDecodeError):
            raw = part.get_payload(decode=True) or b""
            text = raw.decode("utf-8", errors="replace")

        if not isinstance(text, str):
            return

        if content_type == "text/html":
            urls = extract_urls_from_html(text)
            source = "html"
            for href, visible in extract_anchor_pairs(text):
                if not _is_http_like(visible):
                    continue
                mismatch = _normalize_url(visible) != _normalize_url(href)
                rewrite = detect_rewritten_url(href)
                if rewrite:
                    analysis.urls.append(
                        UrlInfo(
                            url=href,
                            source=source,
                            visible_url=visible,
                            href_url=href,
                            mismatch=mismatch,
                            original_url=rewrite.get("original"),
                            rewrite_provider=rewrite.get("provider"),
                        )
                    )
                else:
                    analysis.urls.append(
                        UrlInfo(
                            url=href,
                            source=source,
                            visible_url=visible,
                            href_url=href,
                            mismatch=mismatch,
                        )
                    )
        else:
            urls = extract_urls_from_text(text)
            source = "text"

        for url in urls:
            rewrite = detect_rewritten_url(url)
            if rewrite:
                analysis.urls.append(
                    UrlInfo(
                        url=url,
                        source=source,
                        original_url=rewrite.get("original"),
                        rewrite_provider=rewrite.get("provider"),
                    )
                )
            else:
                analysis.urls.append(UrlInfo(url=url, source=source))

    def _extract_ips_from_part(self, part: Message, analysis: MessageAnalysis) -> None:
        try:
            text = part.get_content()
        except (LookupError, UnicodeDecodeError):
            raw = part.get_payload(decode=True) or b""
            text = raw.decode("utf-8", errors="replace")

        if not isinstance(text, str):
            return

        for ip in extract_ips_from_text(text):
            analysis.ips.append(IpInfo(ip=ip, source="body"))

    def _extract_sender_domain(self, analysis: MessageAnalysis) -> None:
        from_addr = analysis.from_addr or ""
        addr = parseaddr(from_addr)[1]
        if not addr or "@" not in addr:
            return
        domain = addr.split("@", 1)[1].strip().lower()
        if domain:
            analysis.domains.append(DomainInfo(domain=domain))

    def _parse_nested_eml(self, part: Message, payload: bytes, depth: int) -> dict[str, Any]:
        if part.get_content_type() == "message/rfc822":
            nested_payload = part.get_payload()
            if isinstance(nested_payload, list) and nested_payload:
                nested_msg = nested_payload[0]
                return self._parse_message(nested_msg, depth + 1)

        if payload:
            return self.parse_bytes(payload, depth + 1)

        return {"status": "empty"}

    def _analyze_headers(self, msg: Message) -> HeaderAnalysis:
        received_chain = msg.get_all("Received", [])
        auth_results = self._parse_auth_results(msg.get_all("Authentication-Results", []))
        arc_chain = self._analyze_arc_chain(msg)
        timing, mta_anomalies, mta_anomaly_details = self._analyze_timing(
            received_chain, msg.get("Date")
        )
        summary = {
            "message_id": msg.get("Message-Id"),
            "in_reply_to": msg.get("In-Reply-To"),
            "references": msg.get("References"),
            "reply_to": msg.get("Reply-To"),
            "return_path": msg.get("Return-Path"),
            "received_count": len(received_chain),
        }
        return HeaderAnalysis(
            summary=summary,
            received_chain=received_chain,
            auth_results=auth_results,
            arc_chain=arc_chain,
            timing=timing,
            mta_anomalies=mta_anomalies,
            mta_anomaly_details=mta_anomaly_details,
        )

    def _extract_ips_from_headers(
        self, headers: HeaderAnalysis, analysis: MessageAnalysis
    ) -> None:
        for received in headers.received_chain:
            for ip in extract_ips_from_text(received):
                analysis.ips.append(IpInfo(ip=ip, source="received"))

    @staticmethod
    def _parse_auth_results(values: list[str]) -> dict[str, str]:
        results: dict[str, str] = {}
        for item in values:
            for part in item.split(";"):
                part = part.strip()
                if not part:
                    continue
                if "=" in part:
                    key, value = part.split("=", 1)
                    results[key.strip()] = value.strip()
        return results

    @staticmethod
    def _split_addresses(values: list[str]) -> list[str]:
        addresses: list[str] = []
        for name, addr in getaddresses(values):
            if addr:
                addresses.append(addr)
            elif name:
                addresses.append(name)
        return addresses

    @staticmethod
    def _is_eml_attachment(part: Message, filename: str | None) -> bool:
        if part.get_content_type() == "message/rfc822":
            return True
        if filename and filename.lower().endswith(".eml"):
            return True
        return False

    def _write_attachment(
        self, payload: bytes, filename: str | None, content_type: str, depth: int
    ) -> str:
        os.makedirs(self._extract_dir, exist_ok=True)
        safe_name = self._safe_filename(filename)
        if not safe_name:
            safe_name = self._fallback_filename(content_type, depth)

        base_path = os.path.join(self._extract_dir, safe_name)
        final_path = self._dedupe_path(base_path)
        with open(final_path, "wb") as handle:
            handle.write(payload)
        return final_path

    def _fallback_filename(self, content_type: str, depth: int) -> str:
        self._attachment_index += 1
        extension = ".bin"
        if content_type == "message/rfc822":
            extension = ".eml"
        return f"attachment_d{depth}_{self._attachment_index}{extension}"

    @staticmethod
    def _safe_filename(filename: str | None) -> str:
        if not filename:
            return ""
        safe = []
        for ch in filename:
            if ch.isalnum() or ch in {".", "_", "-"}:
                safe.append(ch)
            else:
                safe.append("_")
        sanitized = "".join(safe).strip("._")
        return sanitized[:180]

    @staticmethod
    def _dedupe_path(path: str) -> str:
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        counter = 1
        while True:
            candidate = f"{base}_{counter}{ext}"
            if not os.path.exists(candidate):
                return candidate
            counter += 1

    @staticmethod
    def _analyze_arc_chain(msg: Message) -> dict[str, Any]:
        arc_seals = msg.get_all("ARC-Seal", [])
        arc_msigs = msg.get_all("ARC-Message-Signature", [])
        arc_auths = msg.get_all("ARC-Authentication-Results", [])
        instances = _arc_instances(arc_seals)
        details: list[dict[str, Any]] = []
        cv_pass = 0
        cv_fail = 0
        for seal in arc_seals:
            fields = _arc_fields(seal, ("i", "cv", "d", "s"))
            cv = fields.get("cv", "").lower()
            if cv == "pass":
                cv_pass += 1
            elif cv:
                cv_fail += 1
            details.append({"type": "ARC-Seal", "raw": seal, **fields})
        for sig in arc_msigs:
            fields = _arc_fields(sig, ("i", "d", "s"))
            details.append({"type": "ARC-Message-Signature", "raw": sig, **fields})
        for auth in arc_auths:
            details.append({"type": "ARC-Authentication-Results", "raw": auth})
        status = "ok"
        if not arc_seals and (arc_msigs or arc_auths):
            status = "mismatch"
        if arc_seals:
            expected = list(range(1, len(arc_seals) + 1))
            if instances and instances != expected:
                status = "mismatch"
            if len(arc_msigs) != len(arc_seals) or len(arc_auths) != len(arc_seals):
                status = "mismatch"
        return {
            "seals": len(arc_seals),
            "message_signatures": len(arc_msigs),
            "auth_results": len(arc_auths),
            "instances": instances,
            "status": status,
            "signature_results": {"cv_pass": cv_pass, "cv_fail": cv_fail},
            "details": details,
        }

    @staticmethod
    def _analyze_timing(
        received_chain: list[str], date_header: str | None
    ) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
        anomalies: list[str] = []
        details: list[dict[str, Any]] = []
        received_dates = _parse_received_dates(received_chain)
        date_dt = _parse_date(date_header)
        timing: dict[str, Any] = {}

        if not received_chain:
            anomalies.append("no_received_headers")
            details.append(
                {
                    "code": "no_received_headers",
                    "severity": "medium",
                    "description": "No Received headers found; delivery path cannot be verified.",
                }
            )
        if received_chain and not received_dates:
            anomalies.append("received_dates_unparsable")
            details.append(
                {
                    "code": "received_dates_unparsable",
                    "severity": "low",
                    "description": "Received headers present but dates could not be parsed.",
                }
            )

        if date_dt:
            timing["date_utc"] = date_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        if received_dates:
            first_received = min(received_dates)
            timing["first_received_utc"] = first_received.strftime("%Y-%m-%d %H:%M:%S UTC")
            if date_dt:
                drift_minutes = int((date_dt - first_received).total_seconds() / 60)
                timing["timezone_drift_minutes"] = drift_minutes
                if drift_minutes > 60:
                    anomalies.append("date_after_first_received_over_60m")
                    details.append(
                        {
                            "code": "date_after_first_received_over_60m",
                            "severity": "medium",
                            "description": "Date header is more than 60 minutes after first Received timestamp.",
                            "value": drift_minutes,
                        }
                    )
                if drift_minutes < -1440:
                    anomalies.append("date_before_first_received_over_24h")
                    details.append(
                        {
                            "code": "date_before_first_received_over_24h",
                            "severity": "high",
                            "description": "Date header is more than 24 hours before first Received timestamp.",
                            "value": drift_minutes,
                        }
                    )

            if _has_received_time_inversion(received_dates):
                anomalies.append("received_time_inversion")
                details.append(
                    {
                        "code": "received_time_inversion",
                        "severity": "high",
                        "description": "Received timestamps appear out of order (possible header manipulation).",
                    }
                )

        return timing, anomalies, details


def _is_http_like(value: str) -> bool:
    value = value.strip().lower()
    return value.startswith("http://") or value.startswith("https://")


def _normalize_url(value: str) -> str:
    return value.strip().rstrip("/").lower()


def _detect_password_protection(filename: str | None, payload: bytes) -> dict[str, Any] | None:
    if not payload:
        return None
    name = (filename or "").lower()
    if name.endswith(".zip") or payload.startswith(b"PK\x03\x04") or payload.startswith(b"PK\x05\x06") or payload.startswith(b"PK\x07\x08"):
        # ZIP: check general purpose bit flag for encryption (bit 0)
        if len(payload) >= 8:
            flag = int.from_bytes(payload[6:8], "little")
            encrypted = bool(flag & 0x1)
            return {"type": "zip", "encrypted": encrypted}
    if name.endswith(".pdf") or payload.startswith(b"%PDF"):
        # Look for /Encrypt in PDF trailer
        encrypted = b"/Encrypt" in payload
        return {"type": "pdf", "encrypted": encrypted}
    return None


def _compute_entropy(payload: bytes) -> dict[str, Any] | None:
    if not payload:
        return None
    import math
    if len(payload) < 256:
        return {"value": 0.0, "classification": "small"}
    freq = [0] * 256
    for b in payload:
        freq[b] += 1
    entropy = 0.0
    length = len(payload)
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    classification = "low"
    if entropy >= 7.5:
        classification = "high"
    elif entropy >= 6.5:
        classification = "medium"
    return {"value": round(entropy, 3), "classification": classification}



def _parse_date(value: str | None) -> Any | None:
    if not value:
        return None
    try:
        date_dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if not date_dt:
        return None
    if date_dt.tzinfo is None:
        date_dt = date_dt.replace(tzinfo=timezone.utc)
    return date_dt.astimezone(timezone.utc)


def _parse_received_dates(received_chain: list[str]) -> list[Any]:
    dates = []
    for item in received_chain:
        if ";" not in item:
            continue
        date_part = item.split(";")[-1].strip()
        parsed = _parse_date(date_part)
        if parsed:
            dates.append(parsed)
    return dates


def _has_received_time_inversion(dates: list[Any]) -> bool:
    if len(dates) < 2:
        return False
    for prev, current in zip(dates, dates[1:]):
        if current > prev:
            return True
    return False


def _arc_instances(arc_seals: list[str]) -> list[int]:
    instances = []
    for seal in arc_seals:
        match = re.search(r"\bi=(\d+)", seal)
        if match:
            try:
                instances.append(int(match.group(1)))
            except ValueError:
                continue
    return sorted(instances)


def _arc_fields(value: str, keys: tuple[str, ...]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key in keys:
        match = re.search(rf"\b{key}=([^;\\s]+)", value)
        if match:
            fields[key] = match.group(1)
    return fields


def _build_mime_tree(msg: Message) -> dict[str, Any]:
    node: dict[str, Any] = {
        "content_type": msg.get_content_type(),
        "content_disposition": msg.get_content_disposition(),
        "filename": msg.get_filename(),
        "size": _part_size(msg),
        "children": [],
    }
    if msg.is_multipart():
        for child in msg.iter_parts():
            node["children"].append(_build_mime_tree(child))
    return node


def _part_size(part: Message) -> int:
    if part.is_multipart():
        return 0
    payload = part.get_payload(decode=True)
    if payload is None:
        return 0
    return len(payload)


def _check_attachment_header(
    filename: str | None, content_type: str, payload: bytes
) -> dict[str, Any]:
    if not filename:
        return {"status": "unknown", "reason": "no_filename"}
    guess_type, _ = mimetypes.guess_type(filename)
    if not guess_type:
        return {"status": "unknown", "reason": "unknown_extension"}
    header_type = _detect_magic_type(payload)
    if not header_type:
        header_type = "unknown"
    if guess_type.lower() == content_type.lower():
        return {
            "status": "match",
            "guessed_type": guess_type,
            "content_type": content_type,
            "header_type": header_type,
        }
    return {
        "status": "mismatch",
        "guessed_type": guess_type,
        "content_type": content_type,
        "header_type": header_type,
    }


def _detect_magic_type(payload: bytes) -> str | None:
    if not payload:
        return None
    if payload.startswith(b"%PDF"):
        return "application/pdf"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if payload.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if payload.startswith(b"GIF87a") or payload.startswith(b"GIF89a"):
        return "image/gif"
    if payload.startswith(b"PK\x03\x04"):
        return "application/zip"
    if payload.startswith(b"MZ"):
        return "application/x-msdownload"
    if payload.startswith(b"Rar!\x1a\x07\x00") or payload.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "application/x-rar-compressed"
    if payload.startswith(b"\x1f\x8b\x08"):
        return "application/gzip"
    if payload.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    return None




def _analysis_to_dict(analysis: MessageAnalysis) -> dict[str, Any]:
    return {
        "message_id": analysis.message_id,
        "subject": analysis.subject,
        "from_addr": analysis.from_addr,
        "to_addrs": analysis.to_addrs,
        "date": analysis.date,
        "headers": {
            "summary": analysis.headers.summary,
            "received_chain": analysis.headers.received_chain,
            "auth_results": analysis.headers.auth_results,
            "arc_chain": analysis.headers.arc_chain,
            "timing": analysis.headers.timing,
            "mta_anomalies": analysis.headers.mta_anomalies,
            "mta_anomaly_details": analysis.headers.mta_anomaly_details,
        },
        "mime_tree": analysis.mime_tree,
        "urls": [
            {
                "url": item.url,
                "source": item.source,
                "vt": item.vt,
                "urlscan": item.urlscan,
                "opentip": item.opentip,
                "original_url": item.original_url,
                "rewrite_provider": item.rewrite_provider,
                "visible_url": item.visible_url,
                "href_url": item.href_url,
                "mismatch": item.mismatch,
                "normalized": item.normalized,
                "consensus": item.consensus,
                "screenshot": item.screenshot,
            }
            for item in analysis.urls
        ],
        "domains": [
            {
                "domain": item.domain,
                "mxtoolbox": item.mxtoolbox,
                "opentip": item.opentip,
                "normalized": item.normalized,
                "consensus": item.consensus,
            }
            for item in analysis.domains
        ],
        "ips": [
            {
                "ip": item.ip,
                "source": item.source,
                "abuseipdb": item.abuseipdb,
                "opentip": item.opentip,
                "geoip": item.geoip,
                "normalized": item.normalized,
                "consensus": item.consensus,
            }
            for item in analysis.ips
        ],
        "attachments": [
            {
                "filename": item.filename,
                "content_type": item.content_type,
                "size": item.size,
                "md5": item.md5,
                "sha1": item.sha1,
                "sha256": item.sha256,
                "vt": item.vt,
                "opentip": item.opentip,
                "hybrid": item.hybrid,
                "office_info": item.office_info,
                "pdf_info": item.pdf_info,
                "header_check": item.header_check,
                "normalized": item.normalized,
                "consensus": item.consensus,
                "password_protected": item.password_protected,
                "entropy": item.entropy,
                "is_eml": item.is_eml,
                "saved_path": item.saved_path,
                "nested_eml": _analysis_to_dict(item.nested_eml)
                if isinstance(item.nested_eml, MessageAnalysis)
                else item.nested_eml,
            }
            for item in analysis.attachments
        ],
        "raw_headers": analysis.raw_headers,
    }
