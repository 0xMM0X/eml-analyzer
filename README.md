# EML Analyzer

Full EML triage toolkit built for investigative workflows. It parses message headers and bodies, walks nested EML attachments recursively, extracts URLs, IPs, and attachments, calculates hashes, and enriches findings with threat‑intel lookups. Outputs are available as JSON for deep investigation and as a styled HTML report for quick review.

## Features
- Parses headers and Received chains
- Extracts URLs from text and HTML parts
- Extracts public IPs from headers and bodies
- Computes attachment hashes (MD5/SHA1/SHA256)
- Queries VirusTotal for hashes and URLs (optional)
- Queries AbuseIPDB for IP reputation (optional)
- Submits URLs to urlscan.io with private visibility (optional)
- Recursively analyzes nested EML messages
- Risk scoring (0-10) with clear (<5), medium (=5), and high (>5) levels
- Optional attachment extraction to disk
- JSON and HTML reporting output
- Sender domain MX checks via MxToolbox (optional)
- Office macro extraction with oletools/olefile support
- MIME structure visualization in the HTML report
- Directory scans with include/exclude patterns
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

## Usage

```bash
python -m eml_analyzer.cli -f path\to\message.eml --json
```
Defaults to `path\to\message-report.json`. Use `--json custom.json` to override.

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

You can set these once in `.env` (see `.env.example`).
Report defaults:
- `REPORT_DARK`: Use dark mode HTML by default (true/false)
- `REPORT_SCORE_DETAILS`: Include score breakdown by default (true/false)
- `SCORE_*`: Risk scoring weights (see `.env.example` for full list)

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
