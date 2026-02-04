"""Report rendering helpers."""

from __future__ import annotations

import html
from datetime import datetime, timezone
import itertools
from email.utils import parsedate_to_datetime
import re
from typing import Any


def build_html_report(
    report: dict[str, Any],
    theme: str = "light",
    show_score_details: bool = False,
    theme_overrides: dict[str, str] | None = None,
    defang_urls: bool = False,
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
    palette = _theme_palette(theme, theme_overrides)
    parts.append("body{font-family:'Times New Roman',serif;")
    parts.append(f"background:{palette['body_bg']};")
    parts.append(f"color:{palette['body_fg']};margin:0;padding:24px;")
    parts.append("}")
    parts.append(
        ".container{max-width:1100px;margin:0 auto;display:flex;flex-direction:column;gap:16px;min-width:0;}"
    )
    parts.append(".card{")
    parts.append(f"background:{palette['card_bg']};")
    parts.append(f"border:1px solid {palette['card_border']};")
    parts.append("border-radius:16px;padding:18px;")
    parts.append(f"box-shadow:{palette['card_shadow']};")
    parts.append("overflow:hidden;")
    parts.append("}")
    parts.append(
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;}"
    )
    parts.append(
        ".summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;}"
    )
    parts.append("h1{margin:0 0 8px 0;font-size:2.1rem;}")
    parts.append("h2{margin:0 0 12px 0;font-size:1.4rem;}")
    parts.append("h3{margin:0 0 8px 0;font-size:1.1rem;}")
    parts.append("table{width:100%;max-width:100%;border-collapse:collapse;border-radius:12px;overflow:hidden;table-layout:fixed;}")
    parts.append(
        "th,td{border-bottom:1px solid #efe7db;padding:8px 10px;text-align:left;vertical-align:top;font-size:0.95rem;}"
    )
    parts.append("th,td{overflow-wrap:anywhere;word-break:break-word;}")
    parts.append(f"th{{background:{palette['table_th_bg']};font-weight:bold;color:{palette['table_th_fg']};}}")
    parts.append(f"tr:nth-child(even) td{{background:{palette['table_even_bg']};}}")
    parts.append(f"tr:hover td{{background:{palette['table_hover_bg']};}}")
    parts.append(".pill{display:inline-block;padding:4px 10px;border-radius:999px;")
    parts.append(f"background:{palette['pill_bg']};font-weight:bold;color:{palette['pill_fg']};")
    parts.append("}")
    parts.append(f".small{{color:{palette['small_fg']};font-size:0.9em;}}")
    parts.append(".summary-tile{display:flex;flex-direction:column;gap:6px;}")
    parts.append(f".summary-tile.highlight{{border:1px solid {palette['highlight_border']};}}")
    parts.append(".summary-value{font-size:1.4rem;font-weight:bold;}")
    parts.append(".summary-label{letter-spacing:0.02em;text-transform:uppercase;font-size:0.72rem;}")
    parts.append(".section{margin-top:12px;}")
    parts.append(f".section + .section{{border-top:1px solid {palette['section_border']};padding-top:12px;}}")
    parts.append(".note{margin-top:8px;padding:6px 10px;border-radius:10px;")
    parts.append(f"background:{palette['note_bg']};border:1px solid {palette['note_border']};")
    parts.append(f"color:{palette['note_fg']};font-size:0.85rem;")
    parts.append("}")
    parts.append(".card-stack{display:flex;flex-direction:column;gap:12px;}")
    parts.append(
        ".tag{display:inline-block;background:#1b1a18;color:#fff;border-radius:6px;padding:2px 8px;font-size:0.8rem;}"
    )
    parts.append(".icon-link{margin-left:6px;text-decoration:none;")
    parts.append(f"color:{palette['icon_color']};font-size:0.9rem;display:inline-block;")
    parts.append("}")
    parts.append(f".icon-link:hover{{color:{palette['icon_hover']};}}")
    parts.append(".copy-btn{margin-left:6px;border:none;background:transparent;cursor:pointer;")
    parts.append(f"color:{palette['icon_color']};font-size:0.9rem;opacity:0;transition:opacity 0.15s ease;")
    parts.append("}")
    parts.append(f".copy-btn:hover{{color:{palette['icon_hover']};}}")
    parts.append("td:hover .copy-btn{opacity:1;}")
    parts.append(".tool-actions{display:flex;gap:8px;margin:8px 0;}")
    parts.append(".tool-actions button{border:none;border-radius:999px;padding:4px 10px;cursor:pointer;font-size:0.8rem;font-weight:bold;}")
    if theme == "dark":
        parts.append(".tool-actions button{background:#24344d;color:#eaf1fb;}")
        parts.append(".tool-actions button:hover{background:#2f4566;}")
    else:
        parts.append(".tool-actions button{background:#efe3d1;color:#2a241d;}")
        parts.append(".tool-actions button:hover{background:#e7d8c3;}")
    parts.append(".status-pass{color:#1f6f3b;font-weight:bold;}")
    parts.append(".status-fail{color:#b02a2a;font-weight:bold;}")
    parts.append(".status-neutral{color:#6b5b4a;font-weight:bold;}")
    parts.append(".status-malicious{color:#b02a2a;font-weight:bold;}")
    parts.append(".status-suspicious{color:#cc7a00;font-weight:bold;}")
    parts.append(".status-neutral{color:#6b5b4a;font-weight:bold;}")
    parts.append(".badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:0.8rem;font-weight:bold;}")
    parts.append(f".badge-ok{{background:{palette['badge_ok_bg']};color:{palette['badge_ok_fg']};}}")
    parts.append(f".badge-warn{{background:{palette['badge_warn_bg']};color:{palette['badge_warn_fg']};}}")
    parts.append(".pill-group{display:inline-flex;flex-wrap:wrap;gap:6px;}")
    parts.append(".pill-group{flex-wrap:nowrap;white-space:nowrap;}")
    parts.append(".mini-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:999px;background:rgba(0,0,0,0.06);}")
    parts.append(f".mini-pill{{background:{palette['mini_pill_bg']};}}")
    parts.append(".received-list{list-style:none;margin:0;padding:0;}")
    parts.append(
        ".received-item{background:#f9f4eb;border:1px solid #e6dccd;border-radius:10px;padding:8px 10px;margin-bottom:8px;}"
    )
    parts.append(
        ".received-table td{font-size:0.9rem;line-height:1.4;word-break:break-word;}"
    )
    parts.append(".timeline{display:flex;flex-direction:column;gap:12px;margin-top:10px;}")
    parts.append(".timeline-item{display:grid;grid-template-columns:16px 1fr;gap:12px;}")
    parts.append(".timeline-dot{width:10px;height:10px;border-radius:50%;background:#6c5b47;margin-top:6px;}")
    parts.append(".timeline-line{width:2px;background:rgba(0,0,0,0.15);margin:0 auto;height:100%;}")
    if theme == "dark":
        parts.append(".timeline-dot{background:#7fb2c4;}")
        parts.append(".timeline-line{background:rgba(230,237,242,0.18);}")
    parts.append(".timeline-card{border-radius:10px;padding:10px;border:1px solid rgba(0,0,0,0.08);word-break:break-word;}")
    if theme == "dark":
        parts.append(".timeline-card{border:1px solid rgba(230,237,242,0.12);}")
    parts.append(".mime-tree{list-style:none;margin:0;padding-left:14px;border-left:2px solid rgba(0,0,0,0.08);}")
    if theme == "dark":
        parts.append(".mime-tree{border-left:2px solid rgba(255,255,255,0.08);}")
    parts.append(".mime-node{margin:6px 0;padding-left:10px;position:relative;}")
    parts.append(".mime-node:before{content:'';position:absolute;left:-12px;top:10px;width:10px;height:1px;background:rgba(0,0,0,0.2);}")
    if theme == "dark":
        parts.append(".mime-node:before{background:rgba(255,255,255,0.2);}")
    parts.append(".mime-label{font-weight:bold;}")
    parts.append(".mime-meta{display:inline-flex;gap:6px;flex-wrap:wrap;font-size:0.85rem;color:#6b5b4a;}")
    if theme == "dark":
        parts.append(".mime-meta{color:#a7b7cd;}")
    parts.append(".mime-pill{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;background:rgba(0,0,0,0.06);}")
    if theme == "dark":
        parts.append(".mime-pill{background:rgba(255,255,255,0.1);}")
    parts.append(".cell{display:flex;align-items:center;gap:8px;}")
    parts.append(".cell-value{flex:1;min-width:0;display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;word-break:break-word;}")
    parts.append(".cell .copy-btn{margin-left:auto;}")
    parts.append(".url-cell{min-width:260px;}")
    parts.append(".redirect-cell{min-width:220px;}")
    parts.append(".intel-cell{min-width:140px;}")
    parts.append(".scroll-cell .cell-value{display:block;max-width:320px;white-space:nowrap;overflow:auto;}")
    parts.append(".redirect-cell.scroll-cell .cell-value{max-width:260px;}")
    parts.append(".intel-cell .cell-value{white-space:normal;}")
    parts.append(".table-wrap{overflow-x:visible;}")
    parts.append(".scroll-cell .cell-value::-webkit-scrollbar{height:10px;}")
    parts.append(".scroll-cell .cell-value::-webkit-scrollbar-track{background:rgba(0,0,0,0.06);border-radius:999px;}")
    parts.append(".scroll-cell .cell-value::-webkit-scrollbar-thumb{background:linear-gradient(90deg,#c6b59a,#e2d1b3);border-radius:999px;box-shadow:inset 0 0 2px rgba(0,0,0,0.25);}")
    parts.append(".scroll-cell .cell-value::-webkit-scrollbar-thumb:hover{background:linear-gradient(90deg,#b69f7c,#d9c2a1);}")
    if theme == "dark":
        parts.append(".scroll-cell .cell-value::-webkit-scrollbar-track{background:rgba(230,237,242,0.12);}")
        parts.append(".scroll-cell .cell-value::-webkit-scrollbar-thumb{background:linear-gradient(90deg,#6b8fb0,#8fb2cc);}")
        parts.append(".scroll-cell .cell-value::-webkit-scrollbar-thumb:hover{background:linear-gradient(90deg,#7aa1c2,#a6c6dd);}")
    parts.append(".url-table{table-layout:auto;}")
    if theme == "dark":
        parts.append(".code-block{background:#0f1622;color:#e5eef9;border:1px solid #2f3d52;border-radius:10px;padding:10px;overflow:auto;white-space:pre-wrap;}")
    else:
        parts.append(".code-block{background:#f8f3ea;color:#2a241d;border:1px solid #d6c8b3;border-radius:10px;padding:10px;overflow:auto;white-space:pre-wrap;}")
    parts.append(".raw-block{max-height:180px;overflow:auto;word-break:break-word;}")
    parts.append(".spacer{height:10px;}")
    parts.append(".thumb-wrap{position:relative;display:inline-block;}")
    parts.append(".thumb{cursor:pointer;transition:transform 0.2s ease, box-shadow 0.2s ease;}")
    parts.append(".thumb:hover{transform:scale(1.02);box-shadow:0 10px 22px rgba(0,0,0,0.22);z-index:5;}")
    parts.append(".thumb-overlay{display:none;position:fixed;inset:0;background:rgba(12,12,14,0.45);align-items:center;justify-content:center;z-index:9999;}")
    parts.append(".thumb-overlay img{max-width:45vw;max-height:45vh;border-radius:10px;box-shadow:0 18px 40px rgba(0,0,0,0.35);}")
    parts.append(".thumb-overlay.show{display:flex;}")
    parts.append(".thumb-close{position:absolute;top:18px;right:20px;width:36px;height:36px;border-radius:50%;border:none;background:rgba(0,0,0,0.55);color:#fff;font-size:1.2rem;cursor:pointer;}")
    parts.append(".thumb-close:hover{background:rgba(0,0,0,0.75);}")
    parts.append(".hop-map{display:flex;gap:10px;align-items:center;overflow-x:auto;padding:6px 2px;}")
    parts.append(".hop-node{display:flex;flex-direction:column;align-items:center;gap:4px;min-width:120px;}")
    parts.append(".hop-btn{border:1px solid rgba(0,0,0,0.15);border-radius:999px;padding:6px 10px;cursor:pointer;background:#f6efe4;font-size:0.85rem;}")
    parts.append(".hop-btn.active{background:#e6d7c1;border-color:#d1b998;}")
    parts.append(".hop-line{width:40px;height:2px;background:rgba(0,0,0,0.2);}")
    if theme == "dark":
        parts.append(".hop-btn{background:#1e2a3a;border-color:rgba(230,237,242,0.2);color:#eaf1fb;}")
        parts.append(".hop-btn.active{background:#2b3b52;border-color:#4b6a8c;}")
        parts.append(".hop-line{background:rgba(230,237,242,0.3);}")
    parts.append(".hop-details{margin-top:10px;}")
    parts.append("</style>")
    parts.append("<script>")
    parts.append(
        "function toggleClosestTool(btn, open) {"
        "  var container = btn.closest('.tool-section');"
        "  if (!container) return;"
        "  var items = container.querySelectorAll('details');"
        "  items.forEach(function(item){ item.open = open; });"
        "}"
    )
    parts.append(
        "function toggleThumb(el){"
        "  var wrap = el.closest('.thumb-wrap');"
        "  if (!wrap) return;"
        "  var overlay = wrap.querySelector('.thumb-overlay');"
        "  if (!overlay) return;"
        "  overlay.classList.add('show');"
        "}"
    )
    parts.append(
        "function closeThumb(el){"
        "  el.classList.remove('show');"
        "}"
    )
    parts.append(
        "function closeThumbButton(btn){"
        "  var overlay = btn.closest('.thumb-overlay');"
        "  if (!overlay) return;"
        "  overlay.classList.remove('show');"
        "}"
    )
    parts.append(
        "function selectHop(containerId, idx){"
        "  var container = document.getElementById(containerId);"
        "  if (!container) return;"
        "  var buttons = container.querySelectorAll('.hop-btn');"
        "  buttons.forEach(function(btn){ btn.classList.remove('active'); });"
        "  var active = container.querySelector('[data-hop=\"' + idx + '\"]');"
        "  if (active) active.classList.add('active');"
        "  var detail = container.querySelector('.hop-detail[data-hop=\"' + idx + '\"]');"
        "  container.querySelectorAll('.hop-detail').forEach(function(item){ item.style.display='none'; });"
        "  if (detail) detail.style.display = 'block';"
        "}"
    )
    parts.append("</script>")
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
    parts.append(_render_message(root, 0, defang_urls))
    parts.append("</div>")

    parts.append("</div>")
    parts.append(_copy_script())
    parts.append("</body></html>")
    return "\n".join(parts)


def _render_message(message: dict[str, Any], depth: int, defang_urls: bool) -> str:
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
    summary_table = summary
    reply_to_value = summary.get("reply_to") if summary else None
    from_value = message.get("from_addr")
    mismatch_text = _format_reply_to_mismatch(from_value, reply_to_value)
    if mismatch_text:
        summary_table = dict(summary)
        summary_table["reply_to_vs_from"] = mismatch_text
    parts.append(_key_value_table(summary_table))
    parts.append("</div>")

    if auth:
        parts.append("<div class=\"section\"><h3>Authentication Results</h3>")
        parts.append(_auth_table(auth))
        parts.append("</div>")

    mime_tree = message.get("mime_tree")
    if mime_tree:
        parts.append("<div class=\"section\"><h3>MIME Structure</h3>")
        parts.append(_render_mime_tree(mime_tree))
        parts.append("</div>")

    arc_chain = headers.get("arc_chain", {})
    if arc_chain and (arc_chain.get("details") or arc_chain.get("seals")):
        parts.append("<div class=\"section\"><h3>ARC Chain</h3>")
        parts.append(_arc_chain_table(arc_chain))
        parts.append("</div>")

    timing = headers.get("timing", {})
    anomalies = headers.get("mta_anomalies", [])
    anomaly_details = headers.get("mta_anomaly_details", [])
    if timing or anomalies:
        parts.append("<div class=\"section\"><h3>Timing & MTA</h3>")
        if timing:
            parts.append(_timing_table(timing))
        if anomalies or anomaly_details:
            parts.append(_anomalies_list(anomalies, anomaly_details))
        parts.append("</div>")

    if received:
        timeline_html, timeline_redundant = _received_timeline(received)
        parts.append("<div class=\"section\"><h3>Received Chain</h3>")
        if not timeline_redundant:
            parts.append(_received_table(received))
        parts.append("<div class=\"section\"><h4>Timeline</h4>")
        parts.append(timeline_html)
        parts.append("</div>")
        parts.append("<div class=\"section\"><h4>Hop Map</h4>")
        parts.append(_received_hop_map(received))
        parts.append("</div>")
        parts.append("</div>")

    urls = message.get("urls", [])
    if urls:
        parts.append("<div class=\"section\"><h3>URLs</h3>")
        if any(item.get("opentip") for item in urls):
            parts.append(_opentip_zone_legend())
        show_original = any(item.get("original_url") for item in urls)
        parts.append("<div class=\"table-wrap\">")
        if show_original:
            parts.append(
                "<table class=\"url-table\"><tr><th>URL</th><th>Original</th><th>Redirects</th><th>VT</th><th>URLScan</th><th>OpenTIP</th><th>Screenshot</th></tr>"
            )
        else:
            parts.append(
                "<table class=\"url-table\"><tr><th>URL</th><th>Redirects</th><th>VT</th><th>URLScan</th><th>OpenTIP</th><th>Screenshot</th></tr>"
            )
        for item in urls:
            url_value = str(item.get("url"))
            if defang_urls:
                url_value = _defang(url_value)
            mismatch_flag = item.get("mismatch")
            if mismatch_flag:
                url_value = f"{url_value} (mismatch)"
            vt_summary = _format_vt_summary(item.get("vt"))
            vt_summary = _with_icon_link(vt_summary, _vt_url_link(item.get("url")))
            urlscan_summary = _format_urlscan_summary(item.get("urlscan"))
            urlscan_summary = _with_icon_link(
                urlscan_summary,
                _urlscan_link(item.get("urlscan")),
            )
            opentip_summary = _format_opentip_summary(item.get("opentip"))
            screenshot_html = _format_screenshot(item.get("screenshot"))
            redirect_html = _format_redirect_chain(item.get("redirect_chain"), defang_urls)
            original_value = _format_rewrite(item, defang_urls)
            row_cells = [
                f"<td class=\"url-cell scroll-cell\">{_cell_value(html.escape(url_value), url_value)}</td>",
            ]
            if show_original:
                row_cells.append(
                    f"<td class=\"url-cell scroll-cell\">{_cell_value(_format_table_value(original_value), original_value)}</td>"
                )
            row_cells.append(f"<td class=\"redirect-cell scroll-cell\">{redirect_html}</td>")
            row_cells.extend(
                [
                    f"<td class=\"intel-cell\">{_cell_value(_format_table_value(vt_summary), vt_summary)}</td>",
                    f"<td class=\"intel-cell\">{_cell_value(_format_table_value(urlscan_summary), urlscan_summary)}</td>",
                    f"<td class=\"intel-cell\">{_cell_value(_format_table_value(opentip_summary), opentip_summary)}</td>",
                    f"<td>{_cell_value(screenshot_html, None)}</td>",
                ]
            )
            parts.append("<tr>" + "".join(row_cells) + "</tr>")
        parts.append("</table></div></div>")

    forms = message.get("forms", [])
    if forms:
        parts.append("<div class=\"section\"><h3>Embedded HTML Forms</h3>")
        parts.append(
            "<table><tr><th>Action</th><th>Method</th><th>Inputs</th><th>Password</th><th>File</th><th>Hidden</th><th>External</th><th>Heuristics</th><th>Details</th></tr>"
        )
        for form in forms:
            action = form.get("action") or ""
            action_display = _defang(action) if defang_urls else action
            method = str(form.get("method") or "get").upper()
            inputs_summary = _format_form_inputs_summary(form)
            has_password = "yes" if form.get("has_password") else "no"
            has_file = "yes" if form.get("has_file") else "no"
            hidden = str(form.get("hidden_count") or 0)
            external = "yes" if form.get("external_action") else "no"
            heuristics = _format_form_heuristics(form)
            details = _format_form_details(form)
            parts.append(
                "<tr>"
                f"<td>{_cell_value(html.escape(action_display), action_display)}</td>"
                f"<td>{_cell_value(html.escape(method), method)}</td>"
                f"<td>{_cell_value(html.escape(inputs_summary), inputs_summary)}</td>"
                f"<td>{_cell_value(html.escape(has_password), has_password)}</td>"
                f"<td>{_cell_value(html.escape(has_file), has_file)}</td>"
                f"<td>{_cell_value(html.escape(hidden), hidden)}</td>"
                f"<td>{_cell_value(html.escape(external), external)}</td>"
                f"<td>{_cell_value(html.escape(heuristics), heuristics)}</td>"
                f"<td>{details}</td>"
                "</tr>"
            )
        parts.append("</table></div>")

    ips = message.get("ips", [])
    if ips:
        parts.append("<div class=\"section\"><h3>IPs</h3>")
        if any(item.get("opentip") for item in ips):
            parts.append(_opentip_zone_legend())
        parts.append("<table><tr><th>IP</th><th>AbuseIPDB</th><th>OpenTIP</th><th>GeoIP/ASN</th><th>Consensus</th></tr>")
        for item in ips:
            ip_value = str(item.get("ip"))
            abuse_summary = _format_abuse_summary(item.get("abuseipdb"))
            opentip_summary = _format_opentip_summary(item.get("opentip"))
            geoip_summary = _format_geoip_summary(item.get("geoip"))
            consensus_summary = _format_consensus(item.get("consensus"))
            parts.append(
                "<tr>"
                f"<td>{_cell_value(html.escape(ip_value), ip_value)}</td>"
                f"<td>{_cell_value(_format_table_value(abuse_summary), abuse_summary)}</td>"
                f"<td>{_cell_value(_format_table_value(opentip_summary), opentip_summary)}</td>"
                f"<td>{_cell_value(_format_table_value(geoip_summary), geoip_summary)}</td>"
                f"<td>{_cell_value(_format_table_value(consensus_summary), consensus_summary)}</td>"
                "</tr>"
            )
        parts.append("</table></div>")

    domains = message.get("domains", [])
    if domains:
        parts.append("<div class=\"section\"><h3>Sender Domain</h3>")
        if any(item.get("opentip") for item in domains):
            parts.append(_opentip_zone_legend())
        parts.append(
            "<table><tr><th>Domain</th><th>MxToolbox</th><th>OpenTIP</th><th>Passed</th><th>Warnings</th><th>Failed</th><th>MX Rep</th><th>DNS Server</th><th>Time (ms)</th></tr>"
        )
        for item in domains:
            domain_value = str(item.get("domain"))
            mx_summary = _format_mxtoolbox_summary(item.get("mxtoolbox"))
            mx_passed, mx_warnings, mx_failed = _format_mxtoolbox_sets(item.get("mxtoolbox"))
            mx_rep, mx_dns, mx_time = _format_mxtoolbox_meta(item.get("mxtoolbox"))
            opentip_summary = _format_opentip_summary(item.get("opentip"))
            parts.append(
                "<tr>"
                f"<td>{_cell_value(html.escape(domain_value), domain_value)}</td>"
                f"<td>{_cell_value(_format_table_value(mx_summary), mx_summary)}</td>"
                f"<td>{_cell_value(_format_table_value(opentip_summary), opentip_summary)}</td>"
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
        for idx, item in enumerate(attachments):
            parts.append("<div class=\"card\">")
            attachment_rows: dict[str, Any] = {
                "Filename": item.get("filename"),
                "Content Type": item.get("content_type"),
                "Size": item.get("size"),
                "MD5": item.get("md5"),
                "SHA1": item.get("sha1"),
                "SHA256": item.get("sha256"),
            }
            saved_path = item.get("saved_path")
            if saved_path:
                attachment_rows["Saved Path"] = saved_path
            if item.get("is_eml") is True:
                attachment_rows["Is EML"] = True
            if item.get("vt") is not None:
                attachment_rows["VT"] = _with_icon_link(
                    _format_vt_summary(item.get("vt")),
                    _vt_file_link(item.get("sha256")),
                )
            if item.get("opentip") is not None:
                attachment_rows["OpenTIP"] = _format_opentip_summary(item.get("opentip"))
            if item.get("hybrid") is not None:
                attachment_rows["Hybrid"] = _with_icon_link(
                    _format_hybrid_summary(item.get("hybrid")),
                    _hybrid_link(item.get("sha256")),
                )
            if item.get("office_info"):
                attachment_rows["Office Macros"] = _format_office_summary(
                    item.get("office_info")
                )
            if item.get("pdf_info"):
                attachment_rows["PDF Analysis"] = _format_pdf_summary(item.get("pdf_info"))
                attachment_rows["PDF Heuristics"] = _format_pdf_heuristics(
                    item.get("pdf_info")
                )
            qr_summary = _format_qr_summary(item.get("qr_info"))
            if qr_summary:
                attachment_rows["QR Codes"] = qr_summary
            if item.get("password_protected"):
                attachment_rows["Password Protected"] = _format_password_protection(
                    item.get("password_protected")
                )
            if item.get("entropy"):
                attachment_rows["Entropy"] = _format_entropy(item.get("entropy"))
            if item.get("header_check"):
                attachment_rows["Header Match"] = _format_header_check(item.get("header_check"))
            parts.append(_key_value_table(attachment_rows))
            nested = item.get("nested_eml")
            if isinstance(nested, dict):
                parts.append("<div class=\"section\"><h3>Nested Message</h3>")
                parts.append(_render_message(nested, depth + 1, defang_urls))
                parts.append("</div>")
            pdf_info = item.get("pdf_info") or {}
            if pdf_info:
                parts.append("<div class=\"section tool-section\"><h3>PDF Tools</h3>")
                parts.append(
                    "<div class=\"tool-actions\">"
                    "<button onclick=\"toggleClosestTool(this, true)\">Expand All</button>"
                    "<button onclick=\"toggleClosestTool(this, false)\">Collapse All</button>"
                    "</div>"
                )
                tool_name = html.escape(str(pdf_info.get("tool") or "peepdf"))
                status = html.escape(str(pdf_info.get("status") or "unknown"))
                parts.append("<details>")
                parts.append(f"<summary>{tool_name} ({status})</summary>")
                error = pdf_info.get("error")
                if error:
                    parts.append(f"<div class=\"note\">{html.escape(str(error))}</div>")
                objects_detail = pdf_info.get("objects_detail") or []
                if objects_detail:
                    parts.append("<div class=\"section\"><h4>Objects (decoded)</h4>")
                    for obj in objects_detail:
                        preview = obj.get("decoded_preview") or ""
                        if not preview:
                            continue
                        obj_id = obj.get("id")
                        parts.append("<details>")
                        parts.append(f"<summary>Object {obj_id}</summary>")
                        parts.append(
                            f"<pre class=\"code-block\">{html.escape(str(preview))}</pre>"
                        )
                        if obj.get("decoded_truncated"):
                            parts.append("<div class=\"note\">Object preview truncated.</div>")
                        parts.append("</details>")
                    if pdf_info.get("objects_truncated"):
                        parts.append("<div class=\"note\">Objects list truncated.</div>")
                    parts.append("</div>")
                streams_detail = pdf_info.get("streams_detail") or []
                if streams_detail:
                    parts.append("<div class=\"section\"><h4>Streams (decoded)</h4>")
                    for stream in streams_detail:
                        stream_id = stream.get("id")
                        preview = stream.get("decoded_preview") or ""
                        if not preview:
                            continue
                        parts.append("<details>")
                        parts.append(f"<summary>Stream {stream_id}</summary>")
                        parts.append(
                            f"<pre class=\"code-block\">{html.escape(str(preview))}</pre>"
                        )
                        if stream.get("decoded_truncated"):
                            parts.append("<div class=\"note\">Decoded stream truncated.</div>")
                        parts.append("</details>")
                    if pdf_info.get("streams_truncated"):
                        parts.append("<div class=\"note\">Streams list truncated.</div>")
                    parts.append("</div>")
                parts.append("</details>")

                pdfid = pdf_info.get("pdfid") or {}
                if pdfid:
                    pdfid_status = html.escape(str(pdfid.get("status") or "unknown"))
                    if pdfid.get("status") == "missing":
                        parts.append("<details>")
                        parts.append("<summary>pdfid (missing)</summary>")
                        parts.append("<div class=\"note\">pdfid: not installed</div>")
                        parts.append("</details>")
                    else:
                        parts.append("<details>")
                        parts.append(f"<summary>pdfid ({pdfid_status})</summary>")
                        counts = pdfid.get("counts") or {}
                        if counts:
                            parts.append(_key_value_table(counts))
                        output = pdfid.get("output")
                        if output:
                            parts.append(
                                f"<pre class=\"code-block raw-block\">{html.escape(str(output))}</pre>"
                            )
                        if pdfid.get("truncated"):
                            parts.append("<div class=\"note\">pdfid output truncated.</div>")
                        parts.append("</details>")

                pdf_parser = pdf_info.get("pdf_parser") or {}
                if pdf_parser:
                    parser_status = html.escape(str(pdf_parser.get("status") or "unknown"))
                    if pdf_parser.get("status") == "missing":
                        parts.append("<details>")
                        parts.append("<summary>pdf-parser (missing)</summary>")
                        parts.append("<div class=\"note\">pdf-parser: not installed</div>")
                        parts.append("</details>")
                    else:
                        parts.append("<details>")
                        parts.append(f"<summary>pdf-parser ({parser_status})</summary>")
                        output = pdf_parser.get("output")
                        if output:
                            parts.append(
                                f"<pre class=\"code-block raw-block\">{html.escape(str(output))}</pre>"
                            )
                        if pdf_parser.get("truncated"):
                            parts.append("<div class=\"note\">pdf-parser output truncated.</div>")
                        parts.append("</details>")
                parts.append("</div>")
            qr_info = item.get("qr_info") or {}
            qr_codes = qr_info.get("codes") or []
            qr_error = qr_info.get("error")
            if qr_codes or qr_error:
                tool_name = html.escape(str(qr_info.get("tool") or "qr"))
                status = html.escape(str(qr_info.get("status") or "unknown"))
                parts.append("<div class=\"section tool-section\"><h3>QR Codes</h3>")
                parts.append("<details open>")
                parts.append(f"<summary>{tool_name} ({status})</summary>")
                if qr_error:
                    parts.append(f"<div class=\"note\">{html.escape(str(qr_error))}</div>")
                if qr_codes:
                    for idx_code, code in enumerate(qr_codes, start=1):
                        code_type = html.escape(str(code.get("type") or "QR"))
                        code_data = html.escape(str(code.get("data") or ""))
                        parts.append("<details>")
                        parts.append(f"<summary>Code {idx_code}: {code_type}</summary>")
                        parts.append(f"<pre class=\"code-block\">{code_data}</pre>")
                        parts.append("</details>")
                parts.append("</details>")
                parts.append("</div>")
            office_info = item.get("office_info") or {}
            tool_results = office_info.get("tool_results") or []
            if tool_results:
                parts.append("<div class=\"section tool-section\"><h3>Macro Tools</h3>")
                parts.append(
                    "<div class=\"tool-actions\">"
                    "<button onclick=\"toggleClosestTool(this, true)\">Expand All</button>"
                    "<button onclick=\"toggleClosestTool(this, false)\">Collapse All</button>"
                    "</div>"
                )
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


def _simple_table(headers: list[str], rows_in: list[list[Any]]) -> str:
    rows = []
    rows.append("<table>")
    header_cells = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    rows.append(f"<tr>{header_cells}</tr>")
    for row in rows_in:
        cells = []
        for value in row:
            safe_value = _format_table_value(value)
            cells.append(f"<td>{_cell_value(safe_value, value)}</td>")
        rows.append(f"<tr>{''.join(cells)}</tr>")
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


def _received_timeline(received_chain: list[str]) -> tuple[str, bool]:
    items = []
    redundant = True
    for idx, entry in enumerate(received_chain):
        timestamp = ""
        ts_dt = None
        if ";" in entry:
            timestamp = entry.split(";")[-1].strip()
            try:
                ts_dt = parsedate_to_datetime(timestamp)
            except Exception:
                ts_dt = None
        from_host = _extract_received_field(entry, "from")
        by_host = _extract_received_field(entry, "by")
        with_field = _extract_received_field(entry, "with")
        via_field = _extract_received_field(entry, "via")
        id_field = _extract_received_field(entry, "id")
        for_field = _extract_received_field(entry, "for")

        main_parts = []
        if from_host:
            main_parts.append(f"from {from_host}")
        if by_host:
            main_parts.append(f"by {by_host}")
        main_label = " ".join(main_parts)

        meta_parts = []
        if with_field:
            meta_parts.append(f"with {with_field}")
        if via_field:
            meta_parts.append(f"via {via_field}")
        if id_field:
            meta_parts.append(f"id {id_field}")
        if for_field:
            meta_parts.append(f"for {for_field}")
        meta_label = " · ".join(meta_parts)

        snippet = " ".join(entry.split())
        snippet = snippet.split(";", 1)[0].strip()

        label = main_label or snippet or "Received header"
        if main_label or meta_label:
            redundant = False
        elif label != snippet:
            redundant = False
        items.append(
            {
                "timestamp": timestamp,
                "label": label,
                "meta": meta_label,
                "raw": entry,
                "ts": ts_dt,
                "idx": idx,
            }
        )
    items.sort(
        key=lambda item: (
            item["ts"] or datetime.min.replace(tzinfo=timezone.utc),
            item["idx"],
        )
    )
    parts = ["<div class=\"timeline\">"]
    for idx, item in enumerate(items):
        parts.append("<div class=\"timeline-item\">")
        parts.append("<div>")
        parts.append("<div class=\"timeline-dot\"></div>")
        if idx < len(items) - 1:
            parts.append("<div class=\"timeline-line\"></div>")
        parts.append("</div>")
        parts.append("<div class=\"timeline-card\">")
        ts_dt = item.get("ts")
        if ts_dt:
            if ts_dt.tzinfo is None:
                ts_dt = ts_dt.replace(tzinfo=timezone.utc)
            ts_dt = ts_dt.astimezone(timezone.utc)
            timestamp_value = ts_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            timestamp_value = item.get("timestamp") or ""
        if timestamp_value:
            parts.append(f"<div class=\"small\">{html.escape(timestamp_value)}</div>")
        parts.append(f"<div>{html.escape(item['label'])}</div>")
        if item.get("meta"):
            parts.append(f"<div class=\"small\">{html.escape(item['meta'])}</div>")
        parts.append("</div>")
        parts.append("</div>")
    parts.append("</div>")
    return "\n".join(parts), redundant


_HOP_MAP_COUNTER = itertools.count(1)


def _received_hop_map(received_chain: list[str]) -> str:
    items = []
    for idx, entry in enumerate(received_chain):
        timestamp = ""
        ts_dt = None
        if ";" in entry:
            timestamp = entry.split(";")[-1].strip()
            try:
                ts_dt = parsedate_to_datetime(timestamp)
            except Exception:
                ts_dt = None
        if ts_dt:
            if ts_dt.tzinfo is None:
                ts_dt = ts_dt.replace(tzinfo=timezone.utc)
            ts_dt = ts_dt.astimezone(timezone.utc)
            timestamp = ts_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        from_host = _extract_received_field(entry, "from")
        by_host = _extract_received_field(entry, "by")
        with_field = _extract_received_field(entry, "with")
        via_field = _extract_received_field(entry, "via")
        id_field = _extract_received_field(entry, "id")
        for_field = _extract_received_field(entry, "for")
        label = by_host or from_host or f"Hop {idx + 1}"
        items.append(
            {
                "idx": idx,
                "label": label,
                "from": from_host,
                "by": by_host,
                "with": with_field,
                "via": via_field,
                "id": id_field,
                "for": for_field,
                "timestamp": timestamp,
                "raw": entry,
            }
        )
    items.sort(key=lambda item: item["idx"])

    map_id = f"hop-map-{next(_HOP_MAP_COUNTER)}"
    parts = [f"<div id=\"{map_id}\">"]
    parts.append("<div class=\"hop-map\">")
    for item in items:
        idx = item["idx"]
        label = html.escape(str(item["label"]))
        active_class = " active" if idx == 0 else ""
        parts.append("<div class=\"hop-node\">")
        parts.append(
            f"<button class=\"hop-btn{active_class}\" data-hop=\"{idx}\" onclick=\"selectHop('{map_id}', {idx})\">{label}</button>"
        )
        parts.append("<div class=\"small\">hop</div>")
        parts.append("</div>")
        if idx < len(items) - 1:
            parts.append("<div class=\"hop-line\"></div>")
    parts.append("</div>")

    parts.append("<div class=\"hop-details\">")
    for item in items:
        idx = item["idx"]
        detail_lines = []
        if item.get("timestamp"):
            detail_lines.append(f"timestamp: {item['timestamp']}")
        if item.get("from"):
            detail_lines.append(f"from: {item['from']}")
        if item.get("by"):
            detail_lines.append(f"by: {item['by']}")
        if item.get("with"):
            detail_lines.append(f"with: {item['with']}")
        if item.get("via"):
            detail_lines.append(f"via: {item['via']}")
        if item.get("id"):
            detail_lines.append(f"id: {item['id']}")
        if item.get("for"):
            detail_lines.append(f"for: {item['for']}")
        detail_lines.append("")
        detail_lines.append("raw:")
        detail_lines.append(item.get("raw") or "")
        detail_text = "\n".join(detail_lines).strip()
        style = "display:none;"
        if idx == 0:
            style = "display:block;"
        parts.append(
            f"<div class=\"hop-detail\" data-hop=\"{idx}\" style=\"{style}\">"
            f"<pre class=\"code-block\">{html.escape(detail_text)}</pre>"
            "</div>"
        )
    parts.append("</div>")
    parts.append("</div>")
    return "\n".join(parts)


def _extract_received_field(entry: str, key: str) -> str:
    pattern = re.compile(
        rf"\\b{key}\\s+(.+?)(?=\\s+(?:from|by|with|via|id|for)\\b|;|$)",
        re.IGNORECASE,
    )
    match = pattern.search(entry)
    if not match:
        return ""
    return " ".join(match.group(1).strip().split())


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


def _render_mime_tree(node: dict[str, Any]) -> str:
    def render_node(item: dict[str, Any]) -> str:
        content_type = html.escape(str(item.get("content_type") or ""))
        disposition = html.escape(str(item.get("content_disposition") or ""))
        filename = html.escape(str(item.get("filename") or ""))
        size = item.get("size")
        meta_parts = []
        if disposition:
            meta_parts.append(f"<span class=\"mime-pill\">{disposition}</span>")
        if filename:
            meta_parts.append(f"<span class=\"mime-pill\">file={filename}</span>")
        if isinstance(size, int) and size:
            meta_parts.append(f"<span class=\"mime-pill\">size={size}b</span>")
        meta_html = f"<span class=\"mime-meta\">{''.join(meta_parts)}</span>" if meta_parts else ""
        children = item.get("children") or []
        html_parts = [
            f"<li class=\"mime-node\"><span class=\"mime-label\">{content_type}</span>{meta_html}"
        ]
        if children:
            html_parts.append("<ul class=\"mime-tree\">")
            for child in children:
                html_parts.append(render_node(child))
            html_parts.append("</ul>")
        html_parts.append("</li>")
        return "".join(html_parts)

    return f"<ul class=\"mime-tree\">{render_node(node)}</ul>"


def _arc_chain_table(arc_chain: dict[str, Any]) -> str:
    rows = []
    rows.append("<table>")
    rows.append("<tr><th>Seals</th><th>Message Signatures</th><th>Auth Results</th><th>Instances</th><th>Status</th><th>Signature Results</th></tr>")
    status = arc_chain.get("status", "unknown")
    badge_class = "badge-ok" if status == "ok" else "badge-warn"
    sig_results = arc_chain.get("signature_results") or {}
    sig_text = f"cv_pass={sig_results.get('cv_pass', 0)}, cv_fail={sig_results.get('cv_fail', 0)}"
    rows.append(
        "<tr>"
        f"<td>{arc_chain.get('seals', 0)}</td>"
        f"<td>{arc_chain.get('message_signatures', 0)}</td>"
        f"<td>{arc_chain.get('auth_results', 0)}</td>"
        f"<td>{html.escape(str(arc_chain.get('instances', [])))}</td>"
        f"<td><span class=\"badge {badge_class}\">{html.escape(status)}</span></td>"
        f"<td>{html.escape(sig_text)}</td>"
        "</tr>"
    )
    rows.append("</table>")
    details = arc_chain.get("details") or []
    if details:
        rows.append("<div class=\"section\"><h4>ARC Details</h4>")
        rows.append("<table>")
        rows.append("<tr><th>Type</th><th>i</th><th>d</th><th>s</th><th>cv</th><th>Raw</th></tr>")
        for item in details:
            raw_value = str(item.get("raw", "") or "")
            raw_cell = ""
            if raw_value:
                raw_cell = (
                    "<details>"
                    "<summary>View</summary>"
                    f"<pre class=\"code-block raw-block\">{html.escape(raw_value)}</pre>"
                    "</details>"
                )
            rows.append(
                "<tr>"
                f"<td>{html.escape(str(item.get('type', '')))}</td>"
                f"<td>{html.escape(str(item.get('i', '')))}</td>"
                f"<td>{html.escape(str(item.get('d', '')))}</td>"
                f"<td>{html.escape(str(item.get('s', '')))}</td>"
                f"<td>{html.escape(str(item.get('cv', '')))}</td>"
                f"<td>{raw_cell}</td>"
                "</tr>"
            )
        rows.append("</table>")
        rows.append("</div>")
    return "\n".join(rows)


def _timing_table(timing: dict[str, Any]) -> str:
    rows = []
    rows.append("<table>")
    for key in ("date_utc", "first_received_utc", "timezone_drift_minutes"):
        if key in timing:
            rows.append(f"<tr><th>{html.escape(key)}</th><td>{html.escape(str(timing.get(key)))}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _anomalies_list(anomalies: list[str], details: list[dict[str, Any]]) -> str:
    items = []
    items.append("<div class=\"small\">Anomalies</div>")
    items.append("<ul>")
    if details:
        for item in details:
            code = html.escape(str(item.get("code", "")))
            severity = html.escape(str(item.get("severity", "")))
            description = html.escape(str(item.get("description", "")))
            value = item.get("value")
            value_text = f" (value={value})" if value is not None else ""
            badge_class = "badge-warn" if severity in {"medium", "high"} else "badge-ok"
            items.append(
                f"<li><span class=\"badge {badge_class}\">{severity}</span> {code}: {description}{html.escape(value_text)}</li>"
            )
    else:
        for item in anomalies:
            items.append(f"<li>{html.escape(item)}</li>")
    items.append("</ul>")
    return "\n".join(items)




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
    reply_to_mismatch = breakdown.get("reply_to_mismatch", 0)
    rows.append(
        f"<tr><td>Reply-To vs From</td><td>{'mismatch' if reply_to_mismatch else 'ok'}</td><td>{breakdown.get('reply_to_points', 0)}</td></tr>"
    )
    vt_url = breakdown.get("vt_url") or {}
    rows.append(
        f"<tr><td>VT URL</td><td>malicious={vt_url.get('malicious', 0)}, suspicious={vt_url.get('suspicious', 0)}</td><td>{breakdown.get('vt_url_points', 0)}</td></tr>"
    )
    vt_files = breakdown.get("vt_files") or {}
    rows.append(
        f"<tr><td>VT Files</td><td>malicious={vt_files.get('malicious', 0)}, suspicious={vt_files.get('suspicious', 0)}</td><td>{breakdown.get('vt_files_points', 0)}</td></tr>"
    )
    urlscan = breakdown.get("urlscan") or {}
    rows.append(
        f"<tr><td>urlscan.io</td><td>malicious={urlscan.get('malicious', 0)}</td><td>{breakdown.get('urlscan_points', 0)}</td></tr>"
    )
    hybrid = breakdown.get("hybrid") or {}
    rows.append(
        f"<tr><td>Hybrid Analysis</td><td>malicious={hybrid.get('malicious', 0)}, suspicious={hybrid.get('suspicious', 0)}</td><td>{breakdown.get('hybrid_points', 0)}</td></tr>"
    )
    rows.append(
        f"<tr><td>Executable attachments</td><td>{breakdown.get('executables', 0)}</td><td>{breakdown.get('executables_points', 0)}</td></tr>"
    )
    abuse = breakdown.get("abuseipdb") or {}
    rows.append(
        f"<tr><td>AbuseIPDB</td><td>high={abuse.get('high', 0)}, medium={abuse.get('medium', 0)}, low={abuse.get('low', 0)}</td><td>{breakdown.get('abuse_points', 0)}</td></tr>"
    )
    rows.append(
        f"<tr><td>ARC mismatch</td><td>{breakdown.get('arc_mismatch', 0)}</td><td>{breakdown.get('arc_points', 0)}</td></tr>"
    )
    mta = breakdown.get("mta") or {}
    rows.append(
        f"<tr><td>MTA anomalies</td><td>inversion={mta.get('received_time_inversion', 0)}, after60m={mta.get('date_after_first_received_over_60m', 0)}, before24h={mta.get('date_before_first_received_over_24h', 0)}, no_received={mta.get('no_received_headers', 0)}, unparsable={mta.get('received_dates_unparsable', 0)}</td><td>{breakdown.get('mta_points', 0)}</td></tr>"
    )
    rows.append(
        f"<tr><td>MxToolbox failed</td><td>{breakdown.get('mx_failed', 0)}</td><td>{breakdown.get('mx_points', 0)}</td></tr>"
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


def _format_opentip_summary(opentip: dict[str, Any] | None) -> str:
    if not opentip:
        return "none"
    status = opentip.get("status")
    if status != "ok":
        return _format_error(opentip)
    data = opentip.get("data")
    if isinstance(data, dict):
        parts = []
        zone = data.get("Zone") or data.get("zone") or data.get("ZoneName")
        verdict = data.get("Verdict") or data.get("verdict")
        threat = data.get("Threat") or data.get("threat")
        if zone:
            zone_text = _normalize_zone(str(zone))
            parts.append(zone_text)
        if verdict and verdict not in parts:
            parts.append(str(verdict))
        if threat and threat not in parts:
            parts.append(str(threat))
        if parts:
            return _colorize_opentip_zone(zone_text, ", ".join(parts))
        if data:
            return "ok"
    if isinstance(data, list):
        return f"records={len(data)}"
    if data:
        return str(data)
    return "ok"


def _format_geoip_summary(geoip: dict[str, Any] | None) -> str:
    if not geoip or geoip.get("status") != "ok":
        return "none"
    data = geoip.get("data") or {}
    parts = []
    city = data.get("city")
    region = data.get("region")
    country = data.get("country")
    org = data.get("org")
    if city:
        parts.append(city)
    if region:
        parts.append(region)
    if country:
        parts.append(country)
    if org:
        parts.append(org)
    if parts:
        return ", ".join(parts)
    return "ok"


def _format_consensus(consensus: dict[str, Any] | None) -> str:
    if not consensus:
        return "none"
    verdict = consensus.get("verdict", "unknown")
    top = consensus.get("top_source") or {}
    source_name = top.get("source") or "n/a"
    source_verdict = top.get("verdict") or "unknown"
    return f"{verdict} (top: {source_name}={source_verdict})"


def _format_screenshot(screenshot: dict[str, Any] | None) -> str:
    if not screenshot:
        return "none"
    status = screenshot.get("status")
    if status != "ok":
        return "<span class=\"status-neutral\">screenshot failed</span>"
    data = screenshot.get("data")
    if not data:
        return "ok"
    mime = screenshot.get("mime") or "image/png"
    src = f"data:{mime};base64,{data}"
    title = "Click to enlarge"
    return (
        "<div class=\"thumb-wrap\">"
        f"<img class=\"thumb\" src=\"{src}\" alt=\"screenshot\" title=\"{title}\" style=\"max-width:160px;border-radius:8px;display:block;\" onclick=\"toggleThumb(this)\" />"
        f"<div class=\"thumb-overlay\" onclick=\"closeThumb(this)\">"
        "<button class=\"thumb-close\" onclick=\"closeThumbButton(this);event.stopPropagation();\">×</button>"
        f"<img src=\"{src}\" alt=\"screenshot enlarged\" />"
        "</div>"
        "</div>"
    )


def _format_password_protection(info: dict[str, Any] | None) -> str:
    if not info:
        return "none"
    if info.get("encrypted") is True:
        return f"{info.get('type', 'file')}: encrypted"
    if info.get("encrypted") is False:
        return f"{info.get('type', 'file')}: no encryption"
    return "unknown"


def _format_entropy(info: dict[str, Any] | None) -> str:
    if not info:
        return "none"
    value = info.get("value")
    classification = info.get("classification", "unknown")
    return f"{value} ({classification})"


def _format_qr_summary(qr_info: dict[str, Any] | None) -> str:
    if not qr_info:
        return ""
    codes = qr_info.get("codes") or []
    status = qr_info.get("status")
    if codes:
        return f"{len(codes)} found"
    if status and status != "ok":
        return str(status)
    return ""


def _format_form_inputs_summary(form: dict[str, Any]) -> str:
    count = form.get("input_count")
    type_counts = form.get("input_types") or {}
    if not count and not type_counts:
        return "none"
    parts = []
    for key, value in sorted(type_counts.items()):
        parts.append(f"{key}={value}")
    types_text = ", ".join(parts) if parts else "n/a"
    return f"{count} ({types_text})"


def _format_form_details(form: dict[str, Any]) -> str:
    inputs = form.get("inputs") or []
    if not inputs:
        return "none"
    lines = []
    for item in inputs:
        name = item.get("name") or ""
        input_type = item.get("type") or "text"
        placeholder = item.get("placeholder") or ""
        required = " required" if item.get("required") else ""
        autocomplete = item.get("autocomplete") or ""
        extras = []
        if placeholder:
            extras.append(f"placeholder={placeholder}")
        if autocomplete:
            extras.append(f"autocomplete={autocomplete}")
        extra_text = f" ({', '.join(extras)})" if extras else ""
        label = f"{name or '[unnamed]'} [{input_type}]{required}{extra_text}"
        lines.append(label)
    content = "\n".join(lines)
    return (
        "<details>"
        "<summary>View</summary>"
        f"<pre class=\"code-block\">{html.escape(content)}</pre>"
        "</details>"
    )


def _format_form_heuristics(form: dict[str, Any]) -> str:
    heuristics = form.get("heuristics") or []
    if not heuristics:
        return "none"
    return ", ".join(str(item) for item in heuristics)


def _format_reply_to_mismatch(from_addr: str | None, reply_to: str | None) -> str:
    if not from_addr or not reply_to:
        return ""
    from_domain = _extract_email_domain(from_addr)
    reply_domain = _extract_email_domain(reply_to)
    if not from_domain or not reply_domain:
        return ""
    if from_domain.lower() == reply_domain.lower():
        return "match"
    return f"mismatch ({from_domain} vs {reply_domain})"


def _extract_email_domain(value: str) -> str:
    if "<" in value and ">" in value:
        value = value.split("<", 1)[-1].split(">", 1)[0]
    if "@" not in value:
        return ""
    return value.split("@", 1)[-1].strip()


def _format_redirect_chain(chain_info: dict[str, Any] | None, defang_urls: bool) -> str:
    if not chain_info:
        return "none"
    click_info = None
    server_info = None
    if "click" in chain_info or "server" in chain_info:
        click_info = chain_info.get("click")
        server_info = chain_info.get("server")
    elif chain_info.get("chain"):
        click_info = chain_info

    sections = []
    preview = ""

    if click_info and click_info.get("chain"):
        click_chain = []
        for item in click_info.get("chain") or []:
            text = str(item)
            if defang_urls:
                text = _defang(text)
            click_chain.append(text)
        if click_chain:
            providers = click_info.get("providers") or []
            provider_text = ", ".join(providers) if providers else "tracking"
            sections.append(f"Click chain ({provider_text}):\n" + "\n".join(click_chain))
            preview = click_chain[-1]

    if server_info and server_info.get("chain"):
        server_chain = []
        for item in server_info.get("chain") or []:
            url_text = str(item.get("url") or "")
            status = item.get("status")
            if defang_urls:
                url_text = _defang(url_text)
            suffix = f" [{status}]" if status is not None else ""
            server_chain.append(f"{url_text}{suffix}")
        if server_chain:
            sections.append("Server redirects:\n" + "\n".join(server_chain))
            preview = server_chain[-1].split(" [", 1)[0]
        if server_info.get("error"):
            sections.append(f"Server error: {server_info.get('error')}")

    if not sections:
        return "none"
    if not preview:
        preview = "redirects"
    details = "\n\n".join(sections)
    return (
        "<details>"
        f"<summary>{html.escape(preview)}</summary>"
        f"<pre class=\"code-block\">{html.escape(details)}</pre>"
        "</details>"
    )


def _format_rewrite(item: dict[str, Any], defang_urls: bool) -> str:
    original = item.get("original_url")
    provider = item.get("rewrite_provider")
    if not original:
        return "none"
    if defang_urls:
        original = _defang(str(original))
    if provider:
        return f"{provider}: {original}"
    return str(original)


def _normalize_zone(zone: str) -> str:
    key = zone.strip().lower()
    mapping = {
        "red": "Red (malicious)",
        "orange": "Orange (suspicious)",
        "yellow": "Yellow (not-a-virus)",
        "grey": "Grey (no data)",
        "gray": "Grey (no data)",
        "green": "Green (clean)",
    }
    return mapping.get(key, zone)


def _defang(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def _colorize_opentip_zone(zone_text: str, label: str) -> str:
    key = zone_text.lower()
    if "red" in key:
        return f"<span class=\"status-malicious\">{label}</span>"
    if "orange" in key:
        return f"<span class=\"status-suspicious\">{label}</span>"
    if "yellow" in key:
        return f"<span class=\"status-neutral\">{label}</span>"
    if "green" in key:
        return f"<span class=\"status-pass\">{label}</span>"
    if "grey" in key or "gray" in key:
        return f"<span class=\"status-neutral\">{label}</span>"
    return label


def _opentip_zone_legend() -> str:
    legend = (
        "<div class=\"note\">OpenTIP zones: "
        "<span class=\"pill\">Green: clean</span> "
        "<span class=\"pill\">Grey: no data</span> "
        "<span class=\"pill\">Yellow: not-a-virus</span> "
        "<span class=\"pill\">Orange: suspicious</span> "
        "<span class=\"pill\">Red: malicious</span>"
        "</div>"
    )
    return legend


def _theme_palette(theme: str, overrides: dict[str, str] | None) -> dict[str, str]:
    if theme == "dark":
        palette = {
            "body_bg": "radial-gradient(circle at 12% 0%,#223036,#141b20 62%,#10151a)",
            "body_fg": "#e6edf2",
            "card_bg": "linear-gradient(180deg,#1d252c,#141b21)",
            "card_border": "#2a3a42",
            "card_shadow": "0 16px 36px rgba(0,0,0,0.55)",
            "table_th_bg": "#2a3a42",
            "table_th_fg": "#e6edf2",
            "table_even_bg": "#182027",
            "table_hover_bg": "#22303a",
            "pill_bg": "#2a3a42",
            "pill_fg": "#e6edf2",
            "small_fg": "#aebcc6",
            "highlight_border": "#3b5661",
            "section_border": "rgba(230,237,242,0.12)",
            "note_bg": "#1d252c",
            "note_border": "#2a3a42",
            "note_fg": "#e6edf2",
            "icon_color": "#7fb2c4",
            "icon_hover": "#9ad1e0",
            "badge_ok_bg": "#22323a",
            "badge_ok_fg": "#e6edf2",
            "badge_warn_bg": "#3a2d26",
            "badge_warn_fg": "#e6edf2",
            "mini_pill_bg": "rgba(127,178,196,0.18)",
        }
    else:
        palette = {
            "body_bg": "radial-gradient(circle at top,#f4f0ea,#ebe4d7 60%,#ddd1be)",
            "body_fg": "#1b1a18",
            "card_bg": "#ffffff",
            "card_border": "#d6c8b3",
            "card_shadow": "0 12px 28px rgba(52,36,18,0.12)",
            "table_th_bg": "#efe5d5",
            "table_th_fg": "#2a241d",
            "table_even_bg": "#fbf8f2",
            "table_hover_bg": "#f3eadc",
            "pill_bg": "#efe3d1",
            "pill_fg": "#2a241d",
            "small_fg": "#5b4e3d",
            "highlight_border": "#b8a48a",
            "section_border": "rgba(0,0,0,0.08)",
            "note_bg": "#f6efe4",
            "note_border": "#e4d7c4",
            "note_fg": "#5b4e3d",
            "icon_color": "#6c5b47",
            "icon_hover": "#1b1a18",
            "badge_ok_bg": "#e4f2ea",
            "badge_ok_fg": "#1b5e3c",
            "badge_warn_bg": "#fff1d6",
            "badge_warn_fg": "#8a5a1f",
            "mini_pill_bg": "rgba(0,0,0,0.06)",
        }
    if overrides:
        for key, value in overrides.items():
            palette[key] = value
    return palette


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


def _format_pdf_summary(pdf_info: dict[str, Any] | None) -> str:
    if not pdf_info:
        return "none"
    tool = pdf_info.get("tool", "peepdf")
    status = pdf_info.get("status")
    if status == "missing":
        return f"{tool}: not installed"
    if status == "error":
        error = pdf_info.get("error", "unknown error")
        return f"{tool}: error - {error}"
    parts = []
    version = pdf_info.get("version")
    if version:
        parts.append(f"v{version}")
    objects = pdf_info.get("objects")
    if objects is not None:
        parts.append(f"objects={objects}")
    streams = pdf_info.get("streams")
    if streams is not None:
        parts.append(f"streams={streams}")
    detail = ", ".join(parts) if parts else "ok"
    return f"{tool}: {detail}"


def _format_pdf_heuristics(pdf_info: dict[str, Any] | None) -> str:
    if not pdf_info:
        return "none"
    heuristics = pdf_info.get("heuristics") or {}
    js = heuristics.get("javascript")
    launch = heuristics.get("launch_actions")
    embedded = heuristics.get("embedded_files")
    indicators = heuristics.get("indicators") or []
    parts = [
        f"js={js}" if js is not None else "js=0",
        f"launch={launch}" if launch is not None else "launch=0",
        f"embedded={embedded}" if embedded is not None else "embedded=0",
    ]
    if indicators:
        parts.append(f"indicators: {', '.join(indicators)}")
    return " | ".join(parts)


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


def _format_header_check(check: dict[str, Any] | None) -> str:
    if not check:
        return "unknown"
    status = check.get("status")
    if status == "match":
        guessed = check.get("guessed_type")
        ctype = check.get("content_type")
        header = check.get("header_type")
        return f"match (ext={guessed}, header={ctype}, magic={header})"
    if status == "mismatch":
        guessed = check.get("guessed_type")
        ctype = check.get("content_type")
        header = check.get("header_type")
        return f"mismatch (ext={guessed}, header={ctype}, magic={header})"
    reason = check.get("reason")
    return f"unknown ({reason})" if reason else "unknown"
    
