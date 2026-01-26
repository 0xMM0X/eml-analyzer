"""Correlation view for directory scans."""

from __future__ import annotations

from collections import Counter
from typing import Any


def build_correlation(reports: list[dict[str, Any]]) -> dict[str, Any]:
    senders = Counter()
    subjects = Counter()
    domains = Counter()
    urls = Counter()
    ips = Counter()
    hashes = Counter()
    message_ids = Counter()
    reply_to = Counter()
    return_path = Counter()

    for report in reports:
        root = report.get("root") or {}
        sender = root.get("from_addr")
        if sender:
            senders[sender] += 1
        subject = root.get("subject")
        if subject:
            subjects[subject] += 1
        message_id = root.get("message_id")
        if message_id:
            message_ids[message_id] += 1
        headers = (root.get("headers") or {}).get("summary") or {}
        reply = headers.get("reply_to")
        if reply:
            reply_to[reply] += 1
        rpath = headers.get("return_path")
        if rpath:
            return_path[rpath] += 1

        for domain in root.get("domains") or []:
            value = domain.get("domain")
            if value:
                domains[value] += 1
        for item in root.get("urls") or []:
            value = item.get("url")
            if value:
                urls[value] += 1
        for item in root.get("ips") or []:
            value = item.get("ip")
            if value:
                ips[value] += 1
        for att in root.get("attachments") or []:
            sha256 = att.get("sha256")
            if sha256:
                hashes[sha256] += 1

    return {
        "total_files": len(reports),
        "unique_senders": len(senders),
        "unique_subjects": len(subjects),
        "unique_domains": len(domains),
        "unique_urls": len(urls),
        "unique_ips": len(ips),
        "unique_hashes": len(hashes),
        "top_senders": _top_list(senders),
        "top_subjects": _top_list(subjects),
        "top_domains": _top_list(domains),
        "top_urls": _top_list(urls),
        "top_ips": _top_list(ips),
        "top_attachment_hashes": _top_list(hashes),
        "duplicate_message_ids": _dupe_list(message_ids),
        "top_reply_to": _top_list(reply_to),
        "top_return_path": _top_list(return_path),
    }


def build_correlation_html(data: dict[str, Any]) -> str:
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang=\"en\">")
    parts.append("<head>")
    parts.append("<meta charset=\"utf-8\" />")
    parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />")
    parts.append("<title>EML Correlation Report</title>")
    parts.append("<style>")
    parts.append("body{font-family:'Times New Roman',serif;background:#f5efe6;color:#1b1a18;margin:0;padding:24px;}")
    parts.append(".container{max-width:1100px;margin:0 auto;display:flex;flex-direction:column;gap:16px;}")
    parts.append(".card{background:#ffffff;border:1px solid #d6c8b3;border-radius:16px;padding:18px;box-shadow:0 12px 28px rgba(52,36,18,0.12);}")
    parts.append("h1{margin:0 0 8px 0;font-size:2.1rem;}")
    parts.append("h2{margin:0 0 12px 0;font-size:1.4rem;}")
    parts.append("table{width:100%;border-collapse:collapse;border-radius:12px;overflow:hidden;table-layout:fixed;}")
    parts.append("th,td{border-bottom:1px solid #efe7db;padding:8px 10px;text-align:left;vertical-align:top;font-size:0.95rem;}")
    parts.append("td{word-break:break-word;overflow-wrap:anywhere;}")
    parts.append("th{background:#efe5d5;font-weight:bold;color:#2a241d;}")
    parts.append("tr:nth-child(even) td{background:#fbf8f2;}")
    parts.append("</style>")
    parts.append("</head><body>")
    parts.append("<div class=\"container\">")
    parts.append("<div class=\"card\">")
    parts.append("<h1>Correlation View</h1>")
    parts.append(f"<div>Total files: {data.get('total_files', 0)}</div>")
    parts.append(
        f"<div>Unique senders: {data.get('unique_senders', 0)} | "
        f"Unique subjects: {data.get('unique_subjects', 0)} | "
        f"Unique domains: {data.get('unique_domains', 0)} | "
        f"Unique URLs: {data.get('unique_urls', 0)} | "
        f"Unique IPs: {data.get('unique_ips', 0)} | "
        f"Unique attachment hashes: {data.get('unique_hashes', 0)}</div>"
    )
    parts.append("</div>")

    parts.append(_list_table("Top Senders", data.get("top_senders") or []))
    parts.append(_list_table("Top Subjects", data.get("top_subjects") or []))
    parts.append(_list_table("Top Domains", data.get("top_domains") or []))
    parts.append(_list_table("Top URLs", data.get("top_urls") or []))
    parts.append(_list_table("Top IPs", data.get("top_ips") or []))
    parts.append(_list_table("Top Attachment Hashes", data.get("top_attachment_hashes") or []))
    parts.append(_list_table("Duplicate Message-IDs", data.get("duplicate_message_ids") or []))
    parts.append(_list_table("Top Reply-To", data.get("top_reply_to") or []))
    parts.append(_list_table("Top Return-Path", data.get("top_return_path") or []))

    parts.append("</div></body></html>")
    return "\n".join(parts)


def _list_table(title: str, rows: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    parts.append("<div class=\"card\">")
    parts.append(f"<h2>{_escape(title)}</h2>")
    if not rows:
        parts.append("<div>none</div>")
        parts.append("</div>")
        return "\n".join(parts)
    parts.append("<table><tr><th>Value</th><th>Count</th></tr>")
    for row in rows:
        parts.append(
            "<tr>"
            f"<td>{_escape(row.get('value'))}</td>"
            f"<td>{row.get('count')}</td>"
            "</tr>"
        )
    parts.append("</table></div>")
    return "\n".join(parts)


def _top_list(counter: Counter[str], limit: int = 20) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def _dupe_list(counter: Counter[str], limit: int = 50) -> list[dict[str, Any]]:
    items = [(value, count) for value, count in counter.items() if count > 1]
    items.sort(key=lambda item: item[1], reverse=True)
    return [{"value": value, "count": count} for value, count in items[:limit]]


def _escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
