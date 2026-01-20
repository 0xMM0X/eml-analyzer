"""Report rendering helpers."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re
from typing import Any


def build_html_report(
    report: dict[str, Any], theme: str = "light", show_score_details: bool = False
) -> str:
    root = report.get("root", {})
    stats = report.get("statistics", {})
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang=\"en\">")
    parts.append("<head>")
    parts.append("<meta charset=\"utf-8\" />")
    parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />")
    parts.append("<title>EML Analysis Report</title>")
    parts.append("<style>")
    if theme == "dark":
        parts.append(
            "body{font-family:'Times New Roman',serif;background:radial-gradient(circle at 10% 0%,#243149,#141c2b 55%,#0c111a);color:#e8edf5;margin:0;padding:24px;}"
        )
    else:
        parts.append(
            "body{font-family:'Times New Roman',serif;background:radial-gradient(circle at top,#f4f0ea,#ebe4d7 60%,#ddd1be);color:#1b1a18;margin:0;padding:24px;}"
        )
    parts.append(
        ".container{max-width:1100px;margin:0 auto;display:flex;flex-direction:column;gap:16px;}"
    )
    if theme == "dark":
        parts.append(
            ".card{background:linear-gradient(180deg,#172235,#101826);border:1px solid #2a3850;border-radius:16px;padding:18px;box-shadow:0 16px 36px rgba(0,0,0,0.55);}"
        )
    else:
        parts.append(
            ".card{background:#ffffff;border:1px solid #d6c8b3;border-radius:16px;padding:18px;box-shadow:0 12px 28px rgba(52,36,18,0.12);}"
        )
    parts.append(
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;}"
    )
    parts.append(
        ".summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;}"
    )
    parts.append("h1{margin:0 0 8px 0;font-size:2.1rem;}")
    parts.append("h2{margin:0 0 12px 0;font-size:1.4rem;}")
    parts.append("h3{margin:0 0 8px 0;font-size:1.1rem;}")
    parts.append("table{width:100%;border-collapse:collapse;border-radius:12px;overflow:hidden;}")
    parts.append(
        "th,td{border-bottom:1px solid #efe7db;padding:8px 10px;text-align:left;vertical-align:top;font-size:0.95rem;}"
    )
    if theme == "dark":
        parts.append("th{background:#1f2c41;font-weight:bold;color:#e8edf5;}")
        parts.append("tr:nth-child(even) td{background:#141d2b;}")
        parts.append("tr:hover td{background:#23344d;}")
    else:
        parts.append("th{background:#efe5d5;font-weight:bold;color:#2a241d;}")
        parts.append("tr:nth-child(even) td{background:#fbf8f2;}")
        parts.append("tr:hover td{background:#f3eadc;}")
    if theme == "dark":
        parts.append(".pill{display:inline-block;padding:4px 10px;border-radius:999px;background:#24344d;font-weight:bold;color:#eaf1fb;}")
        parts.append(".small{color:#a9b7cc;font-size:0.9em;}")
    else:
        parts.append(".pill{display:inline-block;padding:4px 10px;border-radius:999px;background:#efe3d1;font-weight:bold;color:#2a241d;}")
        parts.append(".small{color:#5b4e3d;font-size:0.9em;}")
    parts.append(".summary-tile{display:flex;flex-direction:column;gap:6px;}")
    if theme == "dark":
        parts.append(".summary-tile.highlight{border:1px solid #4a5c74;}")
    else:
        parts.append(".summary-tile.highlight{border:1px solid #b8a48a;}")
    parts.append(".summary-value{font-size:1.4rem;font-weight:bold;}")
    parts.append(".summary-label{letter-spacing:0.02em;text-transform:uppercase;font-size:0.72rem;}")
    parts.append(".section{margin-top:12px;}")
    if theme == "dark":
        parts.append(".section + .section{border-top:1px solid rgba(255,255,255,0.08);padding-top:12px;}")
    else:
        parts.append(".section + .section{border-top:1px solid rgba(0,0,0,0.08);padding-top:12px;}")
    parts.append(".card-stack{display:flex;flex-direction:column;gap:12px;}")
    parts.append(
        ".tag{display:inline-block;background:#1b1a18;color:#fff;border-radius:6px;padding:2px 8px;font-size:0.8rem;}"
    )
    if theme == "dark":
        parts.append(".icon-link{margin-left:6px;text-decoration:none;color:#a9b7cc;font-size:0.9rem;display:inline-block;}")
        parts.append(".icon-link:hover{color:#eaf1fb;}")
        parts.append(".copy-btn{margin-left:6px;border:none;background:transparent;cursor:pointer;color:#a9b7cc;font-size:0.9rem;opacity:0;transition:opacity 0.15s ease;}")
        parts.append(".copy-btn:hover{color:#eaf1fb;}")
    else:
        parts.append(".icon-link{margin-left:6px;text-decoration:none;color:#6c5b47;font-size:0.9rem;display:inline-block;}")
        parts.append(".icon-link:hover{color:#1b1a18;}")
        parts.append(".copy-btn{margin-left:6px;border:none;background:transparent;cursor:pointer;color:#6c5b47;font-size:0.9rem;opacity:0;transition:opacity 0.15s ease;}")
        parts.append(".copy-btn:hover{color:#1b1a18;}")
    parts.append("td:hover .copy-btn{opacity:1;}")
    parts.append(".status-pass{color:#1f6f3b;font-weight:bold;}")
    parts.append(".status-fail{color:#b02a2a;font-weight:bold;}")
    parts.append(".status-neutral{color:#6b5b4a;font-weight:bold;}")
    parts.append(".status-malicious{color:#b02a2a;font-weight:bold;}")
    parts.append(".status-suspicious{color:#cc7a00;font-weight:bold;}")
    parts.append(".status-neutral{color:#6b5b4a;font-weight:bold;}")
    parts.append(".pill-group{display:inline-flex;flex-wrap:wrap;gap:6px;}")
    parts.append(".mini-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:999px;background:rgba(0,0,0,0.06);}")
    if theme == "dark":
        parts.append(".mini-pill{background:rgba(255,255,255,0.1);}")
    parts.append(".received-list{list-style:none;margin:0;padding:0;}")
    parts.append(
        ".received-item{background:#f9f4eb;border:1px solid #e6dccd;border-radius:10px;padding:8px 10px;margin-bottom:8px;}"
    )
    parts.append(
        ".received-table td{font-size:0.9rem;line-height:1.4;}"
    )
    parts.append(".cell{display:flex;align-items:center;gap:8px;}")
    parts.append(".cell-value{flex:1;min-width:0;display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;word-break:break-word;}")
    parts.append(".cell .copy-btn{margin-left:auto;}")
    if theme == "dark":
        parts.append(".code-block{background:#0f1622;color:#e5eef9;border:1px solid #2f3d52;border-radius:10px;padding:10px;overflow:auto;white-space:pre-wrap;}")
    else:
        parts.append(".code-block{background:#f8f3ea;color:#2a241d;border:1px solid #d6c8b3;border-radius:10px;padding:10px;overflow:auto;white-space:pre-wrap;}")
    parts.append(".spacer{height:10px;}")
    parts.append("</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<div class=\"container\">")
    parts.append("<div class=\"card\">")
    parts.append("<h1>EML Analysis Report</h1>")
    parts.append("<div class=\"small\">Generated by EML Analyzer</div>")
    parts.append("</div>")
    parts.append("<div class=\"card\">")
    parts.append("<h2>Risk Summary</h2>")
    parts.append("<div class=\"summary-grid\">")
    parts.append(_summary_tile("Risk Score", stats.get("risk_score"), highlight=True))
    parts.append(_summary_tile("Risk Level", stats.get("risk_level"), highlight=True))
    parts.append(_summary_tile("URL Count", stats.get("url_count")))
    parts.append(_summary_tile("IP Count", stats.get("ip_count")))
    parts.append(_summary_tile("Attachment Count", stats.get("attachment_count")))
    parts.append(_summary_tile("Unique Hashes", stats.get("unique_attachment_hashes")))
    parts.append("</div>")
    if show_score_details and stats.get("risk_breakdown"):
        parts.append("<div class=\"section\"><h3>Score Breakdown</h3>")
        parts.append(_score_breakdown_table(stats.get("risk_breakdown")))
        parts.append("</div>")
    parts.append("</div>")

    parts.append("<div class=\"spacer\"></div>")
    parts.append("<div class=\"card\">")
    parts.append("<h2>Root Message</h2>")
    parts.append(_render_message(root, 0))
    parts.append("</div>")

    parts.append("</div>")
    parts.append(_copy_script())
    parts.append("</body></html>")
    return "\n".join(parts)


def _render_message(message: dict[str, Any], depth: int) -> str:
    parts: list[str] = []
    meta = {
        "Message-Id": message.get("message_id"),
        "Subject": message.get("subject"),
        "From": message.get("from_addr"),
        "To": ", ".join(message.get("to_addrs", []) or []),
        "Date": message.get("date"),
    }
    parts.append(_key_value_table(meta))

    headers = message.get("headers", {})
    summary = headers.get("summary", {})
    auth = headers.get("auth_results", {})
    received = headers.get("received_chain", [])

    parts.append("<div class=\"section\"><h3>Header Summary</h3>")
    parts.append(_key_value_table(summary))
    parts.append("</div>")

    if auth:
        parts.append("<div class=\"section\"><h3>Authentication Results</h3>")
        parts.append(_auth_table(auth))
        parts.append("</div>")

    if received:
        parts.append("<div class=\"section\"><h3>Received Chain</h3>")
        parts.append(_received_table(received))
        parts.append("</div>")

    urls = message.get("urls", [])
    if urls:
        parts.append("<div class=\"section\"><h3>URLs</h3>")
        parts.append(
            "<table><tr><th>URL</th><th>VT</th><th>URLScan</th></tr>"
        )
        for item in urls:
            url_value = str(item.get("url"))
            vt_summary = _format_vt_summary(item.get("vt"))
            vt_summary = _with_icon_link(vt_summary, _vt_url_link(item.get("url")))
            urlscan_summary = _format_urlscan_summary(item.get("urlscan"))
            urlscan_summary = _with_icon_link(
                urlscan_summary,
                _urlscan_link(item.get("urlscan")),
            )
            parts.append(
                "<tr>"
                f"<td>{_cell_value(html.escape(url_value), url_value)}</td>"
                f"<td>{_cell_value(_format_table_value(vt_summary), vt_summary)}</td>"
                f"<td>{_cell_value(_format_table_value(urlscan_summary), urlscan_summary)}</td>"
                "</tr>"
            )
        parts.append("</table></div>")

    ips = message.get("ips", [])
    if ips:
        parts.append("<div class=\"section\"><h3>IPs</h3>")
        parts.append("<table><tr><th>IP</th><th>AbuseIPDB</th></tr>")
        for item in ips:
            ip_value = str(item.get("ip"))
            abuse_summary = _format_abuse_summary(item.get("abuseipdb"))
            parts.append(
                "<tr>"
                f"<td>{_cell_value(html.escape(ip_value), ip_value)}</td>"
                f"<td>{_cell_value(_format_table_value(abuse_summary), abuse_summary)}</td>"
                "</tr>"
            )
        parts.append("</table></div>")

    domains = message.get("domains", [])
    if domains:
        parts.append("<div class=\"section\"><h3>Sender Domain</h3>")
        parts.append(
            "<table><tr><th>Domain</th><th>MxToolbox</th><th>Passed</th><th>Warnings</th><th>Failed</th><th>MX Rep</th><th>DNS Server</th><th>Time (ms)</th></tr>"
        )
        for item in domains:
            domain_value = str(item.get("domain"))
            mx_summary = _format_mxtoolbox_summary(item.get("mxtoolbox"))
            mx_passed, mx_warnings, mx_failed = _format_mxtoolbox_sets(item.get("mxtoolbox"))
            mx_rep, mx_dns, mx_time = _format_mxtoolbox_meta(item.get("mxtoolbox"))
            parts.append(
                "<tr>"
                f"<td>{_cell_value(html.escape(domain_value), domain_value)}</td>"
                f"<td>{_cell_value(_format_table_value(mx_summary), mx_summary)}</td>"
                f"<td>{_cell_value(_format_table_value(mx_passed), mx_passed)}</td>"
                f"<td>{_cell_value(_format_table_value(mx_warnings), mx_warnings)}</td>"
                f"<td>{_cell_value(_format_table_value(mx_failed), mx_failed)}</td>"
                f"<td>{_cell_value(html.escape(mx_rep), mx_rep)}</td>"
                f"<td>{_cell_value(html.escape(mx_dns), mx_dns)}</td>"
                f"<td>{_cell_value(html.escape(mx_time), mx_time)}</td>"
                "</tr>"
            )
        parts.append("</table></div>")

    attachments = message.get("attachments", [])
    if attachments:
        parts.append("<div class=\"section\"><h3>Attachments</h3>")
        parts.append("<div class=\"card-stack\">")
        for item in attachments:
            parts.append("<div class=\"card\">")
            parts.append(
                _key_value_table(
                    {
                        "Filename": item.get("filename"),
                        "Content Type": item.get("content_type"),
                        "Size": item.get("size"),
                        "MD5": item.get("md5"),
                        "SHA1": item.get("sha1"),
                        "SHA256": item.get("sha256"),
                        "Saved Path": item.get("saved_path"),
                        "Is EML": item.get("is_eml"),
                        "VT": _with_icon_link(
                            _format_vt_summary(item.get("vt")),
                            _vt_file_link(item.get("sha256")),
                        ),
                        "Hybrid": _with_icon_link(
                            _format_hybrid_summary(item.get("hybrid")),
                            _hybrid_link(item.get("sha256")),
                        ),
                        "Office Macros": _format_office_summary(item.get("office_info")),
                        
                    }
                )
            )
            nested = item.get("nested_eml")
            if isinstance(nested, dict):
                parts.append("<div class=\"section\"><h3>Nested Message</h3>")
                parts.append(_render_message(nested, depth + 1))
                parts.append("</div>")
            office_info = item.get("office_info") or {}
            tool_results = office_info.get("tool_results") or []
            if tool_results:
                parts.append("<div class=\"section\"><h3>Macro Tools</h3>")
                for tool in tool_results:
                    tool_name = html.escape(str(tool.get("tool") or "tool"))
                    tool_status = html.escape(str(tool.get("status") or "unknown"))
                    parts.append("<details>")
                    parts.append(f"<summary>{tool_name} ({tool_status})</summary>")
                    tool_modules = tool.get("modules") or []
                    tool_summaries = tool.get("summaries") or []
                    if tool_summaries:
                        parts.append("<div class=\"section\"><h4>Summaries</h4>")
                        for summary in tool_summaries:
                            name = html.escape(str(summary.get("name") or "module"))
                            line_count = summary.get("line_count")
                            hits = summary.get("keyword_hits") or []
                            preview = html.escape(str(summary.get("preview") or ""))
                            hit_text = ", ".join(hits) if hits else "none"
                            parts.append("<details>")
                            parts.append(
                                f"<summary>{name} (lines: {line_count}, hits: {html.escape(hit_text)})</summary>"
                            )
                            parts.append(f"<pre class=\"code-block\">{preview}</pre>")
                            parts.append("</details>")
                        parts.append("</div>")
                    if tool_modules:
                        parts.append("<div class=\"section\"><h4>Modules</h4>")
                        for module in tool_modules:
                            name = html.escape(str(module.get("name") or "module"))
                            code_text = module.get("code")
                            encoded = module.get("encoded")
                            if code_text:
                                code = html.escape(str(code_text))
                            elif encoded:
                                code = html.escape(f"[base64] {encoded}")
                            else:
                                code = ""
                            parts.append("<details>")
                            parts.append(f"<summary>{name}</summary>")
                            parts.append(f"<pre class=\"code-block\">{code}</pre>")
                            parts.append("</details>")
                        parts.append("</div>")
                    parts.append("</details>")
                parts.append("</div>")
            parts.append("</div>")
        parts.append("</div>")

    return "\n".join(parts)


def _key_value_table(items: dict[str, Any]) -> str:
    rows = []
    rows.append("<table>")
    for key, value in items.items():
        safe_key = html.escape(str(key))
        safe_value = _format_table_value(value)
        rows.append(
            f"<tr><th>{safe_key}</th><td>{_cell_value(safe_value, value)}</td></tr>"
        )
    rows.append("</table>")
    return "\n".join(rows)


def _auth_table(items: dict[str, Any]) -> str:
    rows = []
    rows.append("<table>")
    for key, value in items.items():
        safe_key = html.escape(str(key))
        text_value = "" if value is None else str(value)
        safe_value = html.escape(text_value)
        status_class = _status_class(text_value)
        rows.append(
            "<tr>"
            f"<th>{safe_key}</th>"
            f"<td class=\"{status_class}\">{_cell_value(safe_value, value)}</td>"
            "</tr>"
        )
    rows.append("</table>")
    return "\n".join(rows)


def _status_class(value: str) -> str:
    lowered = value.lower()
    if "pass" in lowered:
        return "status-pass"
    if "fail" in lowered or "softfail" in lowered:
        return "status-fail"
    return "status-neutral"


def _received_table(received_chain: list[str]) -> str:
    rows = []
    rows.append("<table class=\"received-table\">")
    rows.append("<tr><th>Date (UTC)</th><th>Data</th></tr>")
    entries = [_parse_received(item) for item in received_chain]
    entries.sort(key=lambda item: item.get("date_sort") or datetime.max)
    for item in entries:
        date_value = item.get("date") or ""
        raw_value = item.get("raw") or ""
        rows.append(
            "<tr>"
            f"<td class=\"small\">{_cell_value(html.escape(date_value), date_value)}</td>"
            f"<td>{_cell_value(html.escape(raw_value), raw_value)}</td>"
            "</tr>"
        )
    rows.append("</table>")
    return "\n".join(rows)


def _parse_received(value: str) -> dict[str, Any]:
    result: dict[str, Any] = {"raw": value}
    cleaned = " ".join(value.split())
    date_value = None
    if ";" in value:
        date_part = value.split(";")[-1].strip()
        try:
            date_dt = parsedate_to_datetime(date_part)
            if date_dt:
                if date_dt.tzinfo is None:
                    date_dt = date_dt.replace(tzinfo=timezone.utc)
                date_dt = date_dt.astimezone(timezone.utc)
                date_value = date_dt
                result["date"] = date_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (TypeError, ValueError, IndexError):
            date_value = None
            result["date"] = date_part
    result["date_sort"] = date_value
    return result


def _summary_tile(label: str, value: Any, highlight: bool = False) -> str:
    safe_label = html.escape(str(label))
    safe_value = html.escape("" if value is None else str(value))
    highlight_class = " highlight" if highlight else ""
    return (
        f"<div class=\"card summary-tile{highlight_class}\">"
        f"<div class=\"summary-label\">{safe_label}</div>"
        f"<div class=\"summary-value\">{safe_value}</div>"
        "</div>"
    )


def _score_breakdown_table(breakdown: dict[str, Any]) -> str:
    rows = []
    rows.append("<table>")
    rows.append("<tr><th>Signal</th><th>Details</th><th>Points</th></tr>")
    auth = breakdown.get("auth_failures") or []
    rows.append(
        f"<tr><td>Auth failures</td><td>{html.escape(', '.join(auth) or 'none')}</td><td>{breakdown.get('auth_points', 0)}</td></tr>"
    )
    vt_url = breakdown.get("vt_url") or {}
    rows.append(
        f"<tr><td>VT URL</td><td>malicious={vt_url.get('malicious', 0)}, suspicious={vt_url.get('suspicious', 0)}</td><td>{breakdown.get('vt_url_points', 0)}</td></tr>"
    )
    vt_files = breakdown.get("vt_files") or {}
    rows.append(
        f"<tr><td>VT Files</td><td>malicious={vt_files.get('malicious', 0)}, suspicious={vt_files.get('suspicious', 0)}</td><td>{breakdown.get('vt_files_points', 0)}</td></tr>"
    )
    rows.append(
        f"<tr><td>Executable attachments</td><td>{breakdown.get('executables', 0)}</td><td>{breakdown.get('executables_points', 0)}</td></tr>"
    )
    abuse = breakdown.get("abuseipdb") or {}
    rows.append(
        f"<tr><td>AbuseIPDB</td><td>high={abuse.get('high', 0)}, medium={abuse.get('medium', 0)}, low={abuse.get('low', 0)}</td><td>{breakdown.get('abuse_points', 0)}</td></tr>"
    )
    total = breakdown.get("total_before_cap", 0)
    rows.append(f"<tr><td>Total before cap</td><td>{total}</td><td>{total}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _format_vt_summary(vt: dict[str, Any] | None) -> str:
    if not vt:
        return "none"
    status = vt.get("status")
    if status != "ok":
        return _format_error(vt)
    data = vt.get("data") or {}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    malicious_text = _colorize_count("malicious", malicious)
    suspicious_text = _colorize_count("suspicious", suspicious)
    harmless_text = _colorize_count("harmless", harmless, threshold=0, css="status-neutral")
    return _pill_group([malicious_text, suspicious_text, harmless_text])


def _format_urlscan_summary(urlscan: dict[str, Any] | None) -> str:
    if not urlscan:
        return "none"
    status = urlscan.get("status")
    if status != "ok":
        return _format_error(urlscan)
    data = urlscan.get("data") or {}
    verdicts = data.get("verdicts", {})
    overall = verdicts.get("overall", {})
    score = overall.get("score")
    malicious = overall.get("malicious")
    if score is None and malicious is None:
        return "ok"
    malicious_text = _colorize_count("malicious", malicious)
    score_text = _colorize_count("score", score, threshold=0, css="status-neutral")
    return _pill_group([score_text, malicious_text])


def _format_error(payload: dict[str, Any]) -> str:
    error = payload.get("error")
    note = payload.get("note")
    reason = payload.get("reason")
    description = payload.get("description")
    body = payload.get("body")
    if isinstance(body, dict) and not description:
        description = body.get("description") or body.get("message")
    validation = None
    if isinstance(body, dict):
        validation = body.get("validation_errors")
    if validation:
        parts = [item for item in (error, note, reason, description, validation) if item]
    else:
        parts = [item for item in (error, note, reason, description) if item]
    if not parts:
        return payload.get("status", "error")
    return " | ".join(str(item) for item in parts)


def _format_table_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        if "<a " in stripped or "<span " in stripped:
            return stripped
        return html.escape(value)
    return html.escape(str(value))


def _copy_icon(value: Any) -> str:
    text = _plain_text(value)
    if not text:
        return ""
    safe_text = html.escape(text, quote=True)
    return f"<button class=\"copy-btn\" data-copy=\"{safe_text}\" title=\"Copy\">&#128203;</button>"


def _plain_text(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        return str(value)
    text = value
    if "<" in text and ">" in text:
        text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def _cell_value(display_html: str, copy_value: Any) -> str:
    copy_icon = _copy_icon(copy_value)
    if not copy_icon:
        return display_html
    return (
        "<div class=\"cell\">"
        f"<span class=\"cell-value\">{display_html}</span>"
        f"{copy_icon}"
        "</div>"
    )


def _with_icon_link(label: str, link: str) -> str:
    if not label:
        label = ""
    if link:
        return f"{_format_table_value(label)} {link}"
    return _format_table_value(label)


def _vt_url_link(url: str | None) -> str:
    if not url:
        return ""
    url_id = _vt_url_id(url)
    if not url_id:
        return ""
    href = f"https://www.virustotal.com/gui/url/{url_id}"
    return f"<a href=\"{html.escape(href)}\" target=\"_blank\" class=\"icon-link\">&#128279;</a>"


def _vt_file_link(sha256: str | None) -> str:
    if not sha256:
        return ""
    href = f"https://www.virustotal.com/gui/file/{sha256}"
    return f"<a href=\"{html.escape(href)}\" target=\"_blank\" class=\"icon-link\">&#128279;</a>"


def _hybrid_link(sha256: str | None) -> str:
    if not sha256:
        return ""
    href = f"https://www.hybrid-analysis.com/sample/{sha256}"
    return f"<a href=\"{html.escape(href)}\" target=\"_blank\" class=\"icon-link\">&#128279;</a>"


def _vt_url_id(url: str) -> str | None:
    try:
        import base64

        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=")
    except (ValueError, UnicodeError):
        return None


def _copy_script() -> str:
    return """
<script>
document.addEventListener('click', function(event) {
  var target = event.target;
  if (!target.classList.contains('copy-btn')) {
    return;
  }
  var text = target.getAttribute('data-copy') || '';
  if (!text) {
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
  } else {
    var temp = document.createElement('textarea');
    temp.value = text;
    document.body.appendChild(temp);
    temp.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(temp);
  }
});
</script>
"""


def _urlscan_link(urlscan: dict[str, Any] | None) -> str:
    if not urlscan or urlscan.get("status") != "ok":
        return ""
    data = urlscan.get("data") or {}
    result = data.get("result")
    if not result:
        return ""
    return f"<a href=\"{html.escape(str(result))}\" target=\"_blank\" class=\"icon-link\">&#128279;</a>"


def _format_abuse_summary(abuse: dict[str, Any] | None) -> str:
    if not abuse:
        return "none"
    status = abuse.get("status")
    if status != "ok":
        return f"{status}"
    data = (abuse.get("data") or {}).get("data", {})
    confidence = data.get("abuseConfidenceScore")
    reports = data.get("totalReports")
    confidence_text = _colorize_count("confidence", confidence, threshold=50, css="status-suspicious")
    reports_text = _colorize_count("reports", reports, threshold=0, css="status-neutral")
    return _pill_group([confidence_text, reports_text])


def _format_hybrid_summary(hybrid: dict[str, Any] | None) -> str:
    if not hybrid:
        return "none"
    status = hybrid.get("status")
    if status != "ok":
        return _format_error(hybrid)
    data = hybrid.get("data")
    if isinstance(data, list) and data:
        verdicts = []
        for item in data:
            verdict = item.get("verdict")
            if verdict:
                verdicts.append(verdict)
        if verdicts:
            return _pill_group(_colorize_verdicts(sorted(set(verdicts))))
        return f"matches={len(data)}"
    return "ok"


def _format_mxtoolbox_summary(mx: dict[str, Any] | None) -> str:
    if not mx:
        return "none"
    status = mx.get("status")
    if status != "ok":
        return _format_error(mx)
    data = _mxtoolbox_data(mx)
    warnings = data.get("Warnings") or data.get("warnings") or []
    failed = data.get("Failed") or data.get("failed") or []
    passed = data.get("Passed") or data.get("passed") or []
    return f"failed={len(failed)}, warnings={len(warnings)}, passed={len(passed)}"


def _format_mxtoolbox_sets(mx: dict[str, Any] | None) -> tuple[str, str, str]:
    if not mx or mx.get("status") != "ok":
        return ("", "", "")
    data = _mxtoolbox_data(mx)
    passed = data.get("Passed") or data.get("passed") or []
    warnings = data.get("Warnings") or data.get("warnings") or []
    failed = data.get("Failed") or data.get("failed") or []
    return (
        _format_mx_list(passed, "passed"),
        _format_mx_list(warnings, "warnings"),
        _format_mx_list(failed, "failed"),
    )


def _format_mx_list(items: Any, label: str) -> str:
    if not isinstance(items, list) or not items:
        return f"{label}=0"
    names = []
    for item in items[:3]:
        if isinstance(item, dict):
            name = item.get("Name") or item.get("name")
            info = item.get("Info") or item.get("info")
            url = item.get("Url") or item.get("url")
            if name and info:
                names.append(_format_mx_item(f"{name}: {info}", url))
            elif name:
                names.append(_format_mx_item(name, url))
            elif info:
                names.append(_format_mx_item(info, url))
        else:
            names.append(str(item))
    tail = f"{label}={len(items)}"
    if names:
        tail = f"{tail}; " + "; ".join(names)
    return tail


def _format_mx_item(text: str, url: str | None) -> str:
    safe_text = html.escape(text)
    if not url:
        return safe_text
    href = html.escape(str(url))
    return f"{safe_text} <a href=\"{href}\" target=\"_blank\" class=\"icon-link\">&#128279;</a>"


def _mxtoolbox_data(mx: dict[str, Any]) -> dict[str, Any]:
    data = mx.get("data")
    if isinstance(data, list) and data:
        data = data[0]
    if isinstance(data, dict):
        return data
    return mx if isinstance(mx, dict) else {}


def _format_mxtoolbox_meta(mx: dict[str, Any] | None) -> tuple[str, str, str]:
    if not mx or mx.get("status") != "ok":
        return ("", "", "")
    data = _mxtoolbox_data(mx)
    mx_rep = str(data.get("MxRep") or data.get("mxRep") or "")
    dns = str(data.get("ReportingNameServer") or data.get("reportingNameServer") or "")
    time_ms = str(data.get("TimeToComplete") or data.get("timeToComplete") or "")
    return (mx_rep, dns, time_ms)


def _colorize_count(
    label: str, value: Any, threshold: int = 1, css: str = "status-malicious"
) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return f"{label}={value}"
    if number >= threshold and label == "suspicious":
        return f"{label}=<span class=\"status-suspicious\">{number}</span>"
    if number >= threshold:
        return f"{label}=<span class=\"{css}\">{number}</span>"
    return f"{label}={number}"


def _colorize_verdicts(verdicts: list[str]) -> list[str]:
    parts = []
    for verdict in verdicts:
        verdict_lower = verdict.lower()
        if "malicious" in verdict_lower:
            parts.append(f"<span class=\"status-malicious\">{html.escape(verdict)}</span>")
        elif "suspicious" in verdict_lower:
            parts.append(f"<span class=\"status-suspicious\">{html.escape(verdict)}</span>")
        else:
            parts.append(html.escape(verdict))
    return parts


def _pill_group(items: list[str]) -> str:
    pills = []
    for item in items:
        pills.append(f"<span class=\"mini-pill\">{item}</span>")
    return f"<span class=\"pill-group\">{''.join(pills)}</span>"


def _format_office_summary(office_info: dict[str, Any] | None) -> str:
    if not office_info:
        return "none"
    has_macros = office_info.get("has_macros")
    if not has_macros:
        return f"{office_info.get('office_type', 'office')}: no macros"
    modules = office_info.get("macro_modules") or []
    names = office_info.get("macro_names") or []
    if modules:
        module_names = [module.get("name") for module in modules if module.get("name")]
        if module_names:
            return (
                f"{office_info.get('office_type', 'office')}: modules="
                f"{', '.join(module_names)}"
            )
        return f"{office_info.get('office_type', 'office')}: modules={len(modules)}"
    if names:
        return f"{office_info.get('office_type', 'office')}: {', '.join(names)}"
    hits = office_info.get("string_hits") or []
    if hits:
        return f"{office_info.get('office_type', 'office')}: {hits[0]}"
    return f"{office_info.get('office_type', 'office')}: macros present"


def _format_macro_parse(office_info: dict[str, Any] | None) -> str:
    if not office_info:
        return "n/a"
    status = office_info.get("macro_parse")
    if not status:
        return "n/a"
    return status


def _format_macro_tool(office_info: dict[str, Any] | None) -> str:
    if not office_info:
        return "n/a"
    status = office_info.get("macro_parse")
    if status == "olevba":
        return "oletools (olevba)"
    if status == "ok":
        return "olefile (custom)"
    if status == "olefile_missing":
        return "olefile (missing)"
    if status == "no_modules":
        return "olefile (no modules)"
    return status or "n/a"
