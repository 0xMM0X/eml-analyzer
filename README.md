# EML Analyzer

![Cover](Cover.png)

Full EML triage toolkit built for investigative workflows. It parses message headers and bodies, walks nested EML attachments recursively, extracts URLs, IPs, and attachments, calculates hashes, and enriches findings with threat‑intel lookups. Outputs are available as JSON for deep investigation and as a styled HTML report for quick review.

## Features
- Parses headers and Received chains
- Extracts URLs from text and HTML parts
- Extracts public IPs from headers and bodies
- Computes attachment hashes (MD5/SHA1/SHA256)
- Queries VirusTotal for hashes and URLs (optional)
- Queries AbuseIPDB for IP reputation (optional)
- Queries Kaspersky OpenTIP for hashes, URLs, IPs, and domains (optional)
- Submits URLs to urlscan.io with private visibility (optional)
- Recursively analyzes nested EML messages
- Risk scoring (0-10) with clear (<5), medium (=5), and high (>5) levels
- Optional attachment extraction to disk
- JSON and HTML reporting output
- Sender domain MX checks via MxToolbox (optional)
- Office macro extraction with oletools/olefile support
- PDF attachment analysis with peepdf (optional) + structure heuristics (JS/Launch/Embedded)
- MIME structure visualization in the HTML report
- Directory scans with include/exclude patterns
- Correlation view across multiple EMLs in directory scans (summary report)
- Timing drift and MTA anomaly detection
- Attachment magic-byte header verification

## Setup

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Optional (full VBA macro bodies):

```bash
pip install olefile
```

Preferred (olevba decoding for macro extraction):

```bash
pip install oletools
```

Optional (PDF attachment analysis):

```bash
pip install peepdf-3
```

Optional (pdfid from pip):

```bash
pip install pdfid
```

Optional (pdf-parser.py from DidierStevensSuite) OR just set the tool installing flag to true:

```bash
curl -L https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py -o pdf-parser.py
```

## Usage

```bash
python -m eml_analyzer.cli -f path\to\message.eml --json
```
Defaults to `path\to\message-report.json`. Use `--json custom.json` to override.

If neither `--json` nor `--html` are provided, the CLI now writes both by default.

Write both JSON and HTML reports:

```bash
python -m eml_analyzer.cli -f message.eml --json --html
```
Analyze a directory of EML files (writes to `output/` under the directory):

```bash
python -m eml_analyzer.cli -d path\to\emls --json --html
```
Recursive directory scan with filters:

```bash
python -m eml_analyzer.cli -d path\to\emls --recursive --include "*.eml" --exclude "*newsletter*"
```
Dark mode HTML:

```bash
python -m eml_analyzer.cli -f message.eml --html --dark
```
Add verbose debugging:

```bash
python -m eml_analyzer.cli -f message.eml --json --html -v
```
Include score calculation details:

```bash
python -m eml_analyzer.cli -f message.eml --json --html --score-details
```
Defaults to `message-report.json` and `message-report.html`.

Extract attachments:

```bash
python -m eml_analyzer.cli -f message.eml -e --extract-dir extracted_files
```
If `--extract-dir` is omitted, attachments are saved alongside the input EML.

Optional VirusTotal API key:

```bash
set VT_API_KEY=your_key_here
python -m eml_analyzer.cli -f message.eml --output report.json
```

Submit URLs to VirusTotal if no report exists:

```bash
python -m eml_analyzer.cli -f message.eml --allow-url-submission
```

## Configuration (Environment Variables)
- `VT_API_KEY`: VirusTotal API key
- `VT_TIMEOUT_SECONDS`: Request timeout (default: 20)
- `MAX_BYTES_FOR_HASH`: Limit bytes hashed per attachment
- `VT_ALLOW_URL_SUBMISSION`: Allow URL submission (true/false)
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key
- `URLSCAN_API_KEY`: urlscan.io API key
- `HYBRID_API_KEY`: Hybrid Analysis API key
- `MXTOOLBOX_API_KEY`: MxToolbox API key
- `OPENTIP_API_KEY`: Kaspersky OpenTIP API token

You can set these once in `.env` (see `.env.example`).
Report defaults:
- `REPORT_DARK`: Use dark mode HTML by default (true/false)
- `REPORT_SCORE_DETAILS`: Include score breakdown by default (true/false)
- `SCORE_*`: Risk scoring weights (see `.env.example` for full list)
- `TOOLS_AUTO_DOWNLOAD`: Auto-download external tools if missing (true/false)
- `REPORT_THEME_FILE`: Path to a JSON palette file for HTML reports
- `IOC_CACHE_DB`: SQLite cache path for IOC de-duplication across runs
- `IOC_CACHE_TTL_HOURS`: Cache TTL in hours (optional)

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

## Output
The report is JSON containing root message analysis, nested EML details, URL findings, attachment hashes, optional VirusTotal results, and `risk_score`/`risk_level` fields in `statistics`.

## Risk Scoring
The risk score is a 0-10 value built from multiple signals and capped at 10:
- Authentication failures: `spf`, `dkim`, or `dmarc` with fail/softfail adds +2 each.
- VirusTotal URL results: malicious adds +5, suspicious adds +3.
- VirusTotal file results: malicious adds +6, suspicious adds +3.
- Executable attachments add +1 (e.g., `.exe`, `.js`, `.ps1`).
- AbuseIPDB confidence: >=80 adds +5, >=50 adds +3, >=25 adds +1.

Risk level mapping:
- Clear: score < 5
- Medium: score = 5
- High: score > 5

## Planned Features
- URL/attachment sandboxing integrations (open-source detonation feeds)
- Add automated PDF structure heuristics (JS, launch actions, embedded files)
- Auto-cluster similar emails by subject similarity and sender domain.
- Safe link rewrite detection (proofpoint/securelink).
- Thread timeline view (visual hop graph for Received chain).
- GeoIP + ASN enrichment for IPs.
- Attachment password-protection detection (zip/pdf).
- Click‑tracking redirect chain expansion.
- URL landing page screenshot via headless browser (optional).
- QR code extraction from images/PDFs.
- Reply-to vs From mismatch scoring + display.
- Threat intel normalization across vendors (schema + verdict mapping).
- Embedded HTML form extraction + analysis.
- URL defanging toggle in reports.
- IP reputation consensus scoring (multi‑source).
- Risk score explanation as a JSON‑driven policy file.
- Attachment entropy scoring (packed/encrypted heuristic).
- Compare visible links vs href mismatch.


### Please feel free to provide any recommendations or contribute enhancements to the tool as you see fit.
