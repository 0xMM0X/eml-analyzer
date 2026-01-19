"""EML parsing and analysis."""

from __future__ import annotations

import email
import os
from email import policy
from email.message import Message
from email.utils import getaddresses
from typing import Any

from .hashing import hash_bytes
from .log_utils import log
from .office_utils import analyze_office_attachment
from .ip_utils import extract_ips_from_text
from .models import AttachmentInfo, HeaderAnalysis, IpInfo, MessageAnalysis, UrlInfo
from .url_utils import extract_urls_from_html, extract_urls_from_text
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
        else:
            urls = extract_urls_from_text(text)
            source = "text"

        for url in urls:
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
        },
        "urls": [
            {
                "url": item.url,
                "source": item.source,
                "vt": item.vt,
                "urlscan": item.urlscan,
            }
            for item in analysis.urls
        ],
        "ips": [
            {"ip": item.ip, "source": item.source, "abuseipdb": item.abuseipdb}
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
                "hybrid": item.hybrid,
                "office_info": item.office_info,
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
