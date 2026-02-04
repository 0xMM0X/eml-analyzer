# EML Analyzer

![Cover](Cover.png)

EML Analyzer is a professional‑grade email triage toolkit for security analysts. It parses headers and bodies, walks nested EML attachments, extracts IOCs, calculates hashes, and enriches findings with optional threat‑intel lookups. Results are delivered as structured JSON for investigations and a polished HTML report for quick review.

## Table of Contents
1. [Overview](#overview)
2. [Capabilities](#capabilities)
3. [Install](#install)
4. [Quick Start](#quick-start)
5. [Usage](#usage)
6. [Configuration](#configuration)
7. [Output](#output)
8. [Risk Scoring](#risk-scoring)
9. [Planned Features](#planned-features)

## Overview
- Purpose‑built for email forensics and phishing triage
- Recursive EML parsing with attachment analysis
- IOC enrichment across multiple vendors (optional)
- Analyst‑friendly HTML reports + JSON for automation

## Capabilities

**Core Analysis**
- Header parsing, Received chains, and timing/MTA anomaly detection
- URL extraction (text/HTML), click‑tracking expansion, optional server‑side redirects
- IP extraction from headers and bodies
- Attachment hashing (MD5/SHA1/SHA256)
- Recursive nested EML analysis
- MIME structure visualization
- Risk scoring (0‑10) with clear/medium/high levels
- JSON + HTML reporting
- Directory scans with include/exclude patterns
- Correlation view across multi‑EML scans
- Subject clustering by similarity + sender domain
- Reply‑To vs From mismatch scoring + display
- Interactive hop map for header path visualization

**Threat Intel (Optional)**
- VirusTotal (hash + URL)
- AbuseIPDB (IP reputation)
- Kaspersky OpenTIP (hash/URL/IP/domain)
- urlscan.io (URL scanning)
- Hybrid Analysis (hash lookup)
- MxToolbox (sender domain MX checks)
- GeoIP + ASN enrichment (ipinfo.io)

**Attachment Analysis (Optional)**
- Office macro extraction (oletools/olefile)
- PDF inspection (peepdf + pdfid + pdf-parser)
- PDF structure heuristics (JS/Launch/Embedded)
- Password‑protection detection (ZIP/PDF)
- Entropy scoring (packed/encrypted heuristic)
- QR code extraction from images/PDFs
- Embedded HTML form extraction + analysis
- URL landing page screenshots (Playwright)

---

## Install

Minimal install:
```bash
pip install -r requirements.txt
```

Full install (all optional integrations):
```bash
pip install -r requirements.full.txt
```

Optional tools:
```bash
pip install oletools
pip install olefile
pip install peepdf-3
pip install pdfid
pip install pillow pyzbar pymupdf
```

Optional (pdf-parser.py from DidierStevensSuite), or set `TOOLS_AUTO_DOWNLOAD=true`:
```bash
curl -L https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py -o pdf-parser.py
```

---

## Quick Start
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python -m eml_analyzer.cli -f path\to\message.eml --json --html
```

---

## Usage

Single file:
```bash
python -m eml_analyzer.cli -f path\to\message.eml --json
```

Write both JSON + HTML (default if neither is provided):
```bash
python -m eml_analyzer.cli -f message.eml --json --html
```

Directory scan:
```bash
python -m eml_analyzer.cli -d path\to\emls --json --html
```

Recursive scan with filters:
```bash
python -m eml_analyzer.cli -d path\to\emls --recursive --include "*.eml" --exclude "*newsletter*"
```

Dark mode report:
```bash
python -m eml_analyzer.cli -f message.eml --html --dark
```

Verbose + debug:
```bash
python -m eml_analyzer.cli -f message.eml --json --html -v --debug
```

Extract attachments:
```bash
python -m eml_analyzer.cli -f message.eml -e --extract-dir extracted_files
```
If `--extract-dir` is omitted, attachments are saved next to the input EML.

---

## Configuration

You can set these in `.env` (see `.env.example`).

| Variable | Description | Default |
|---|---|---|
| `VT_API_KEY` | VirusTotal API key |  |
| `VT_TIMEOUT_SECONDS` | VT request timeout | 20 |
| `MAX_BYTES_FOR_HASH` | Limit bytes hashed per attachment |  |
| `VT_ALLOW_URL_SUBMISSION` | Submit URLs if not found | false |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |  |
| `URLSCAN_API_KEY` | urlscan.io API key |  |
| `HYBRID_API_KEY` | Hybrid Analysis API key |  |
| `MXTOOLBOX_API_KEY` | MxToolbox API key |  |
| `OPENTIP_API_KEY` | Kaspersky OpenTIP API token |  |
| `IPINFO_API_KEY` | ipinfo.io token for GeoIP/ASN |  |
| `REPORT_DARK` | Dark mode HTML by default | false |
| `REPORT_SCORE_DETAILS` | Include score breakdown | false |
| `REPORT_DEFANG_URLS` | Defang URLs in HTML | false |
| `REPORT_THEME_FILE` | JSON palette file |  |
| `VERBOSE` | Verbose logging | false |
| `DEBUG` | Detailed debug logging | false |
| `DEBUG_LOG_FILE` | Write logs to file |  |
| `URL_SCREENSHOT_ENABLED` | Enable URL screenshots | false |
| `URL_SCREENSHOT_TIMEOUT_MS` | Screenshot timeout | 20000 |
| `URL_REDIRECT_RESOLVE` | Resolve server redirects | false |
| `URL_REDIRECT_ONLY_TRACKED` | Only resolve tracked URLs | false |
| `URL_REDIRECT_MAX_HOPS` | Max redirect hops | 5 |
| `URL_REDIRECT_TIMEOUT_SECONDS` | Redirect timeout | 10 |
| `IOC_CACHE_DB` | IOC cache DB path |  |
| `IOC_CACHE_TTL_HOURS` | Cache TTL in hours |  |
| `TOOLS_AUTO_DOWNLOAD` | Auto-download external tools | false |
| `SCORE_*` | Scoring weights | see `.env.example` |

Custom theme file example:
```json
{
  "dark": {
    "body_bg": "radial-gradient(circle at 12% 0%,#222833,#141920 62%,#0f141a)",
    "body_fg": "#e6edf2",
    "card_bg": "linear-gradient(180deg,#1b222b,#141a21)",
    "card_border": "#2a3340",
    "table_th_bg": "#2a3340",
    "table_th_fg": "#e6edf2",
    "table_even_bg": "#171e26",
    "table_hover_bg": "#222a36",
    "pill_bg": "#2a3340",
    "pill_fg": "#e6edf2",
    "small_fg": "#aeb7c4",
    "highlight_border": "#3a4a5a",
    "section_border": "rgba(230,237,242,0.12)",
    "note_bg": "#1b222b",
    "note_border": "#2a3340",
    "note_fg": "#e6edf2",
    "icon_color": "#7fb2c4",
    "icon_hover": "#9ad1e0",
    "badge_ok_bg": "#22303a",
    "badge_ok_fg": "#e6edf2",
    "badge_warn_bg": "#3a2d26",
    "badge_warn_fg": "#e6edf2",
    "mini_pill_bg": "rgba(127,178,196,0.18)"
  }
}
```

---

## Output

The JSON report includes root message analysis, nested EML details, URLs/IPs/attachments, optional intel results, and `risk_score` / `risk_level` in `statistics`.

---

## Risk Scoring

Signals (capped at 10):
- Authentication failures (`spf`, `dkim`, `dmarc`): +2 each
- VirusTotal URL: malicious +5, suspicious +3
- VirusTotal file: malicious +6, suspicious +3
- Executable attachments: +1
- AbuseIPDB confidence: >=80 +5, >=50 +3, >=25 +1

Risk levels:
- Clear: score < 5
- Medium: score = 5
- High: score > 5

---

## Planned Features
- URL/attachment sandboxing integrations (open-source detonation feeds)
- Risk score explanation as a JSON‑driven policy file

---

Feel free to open an issue or suggest enhancements.
