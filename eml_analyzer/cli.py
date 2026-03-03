"""CLI entrypoint for EML Analyzer."""

import argparse
import json
import sys
import os
import base64
import zipfile
import subprocess
from pathlib import Path
import requests

from .analyzer import EmlAnalyzer
from .config import AnalyzerConfig
from .correlation import build_correlation, build_correlation_html
from .reporting import build_html_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze EML files with recursive parsing.")
    parser.add_argument(
        "-f",
        "--file",
        dest="eml",
        help="Path to the EML file to analyze.",
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="Analyze all .eml files in a directory.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan directories when using -d.",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        help="Include glob pattern(s) for directory scans (default: *.eml).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude glob pattern(s) for directory scans.",
    )
    parser.add_argument(
        "--json",
        nargs="?",
        const=True,
        help="Write JSON output (optional path). Defaults to <eml>-report.json.",
    )
    parser.add_argument(
        "--html",
        nargs="?",
        const=True,
        help="Write HTML output (optional path). Defaults to <eml>-report.html.",
    )
    parser.add_argument(
        "-e",
        "--extract-attachments",
        action="store_true",
        help="Extract attachments to disk.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable detailed debug logging with tracebacks.",
    )
    parser.add_argument(
        "--debug-log",
        help="Write debug logs to the specified file instead of stderr.",
    )
    parser.add_argument(
        "--dark",
        action="store_true",
        help="Generate a dark mode HTML report.",
    )
    parser.add_argument(
        "--defang-urls",
        action="store_true",
        help="Defang URLs in HTML report output.",
    )
    parser.add_argument(
        "--score-details",
        action="store_true",
        help="Include risk score breakdown details in outputs.",
    )
    parser.add_argument(
        "--extract-dir",
        help="Directory to write extracted attachments (default: same directory as input).",
    )
    parser.add_argument(
        "--embed-attachments",
        action="store_true",
        help="Embed attachment bytes (base64) into JSON/HTML report for later extraction.",
    )
    parser.add_argument(
        "--extract-from-report",
        help="Extract embedded attachments from an existing JSON report file.",
    )
    parser.add_argument(
        "--skip-enrichments",
        action="store_true",
        help="Skip all external enrichment lookups/APIs.",
    )
    parser.add_argument(
        "--skip-macros",
        action="store_true",
        help="Skip Office macro extraction/analysis.",
    )
    parser.add_argument(
        "--case-bundle",
        nargs="?",
        const=True,
        help="All-in-one bundle mode: generate JSON+HTML, extract attachments, write logs, and zip per EML (optional output dir/.zip path).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.extract_from_report and not args.eml and not args.dir:
        parser.error("Either -f/--file or -d/--dir is required.")

    config = AnalyzerConfig.from_env()
    verbose = args.verbose or config.verbose
    debug = args.debug or config.debug
    if debug:
        verbose = True
    debug_log_path = args.debug_log or config.debug_log_file
    if debug_log_path and not args.case_bundle:
        from .log_utils import set_log_file

        set_log_file(debug_log_path)
    analyzer = EmlAnalyzer(config, verbose=verbose, debug=debug)
    update_messages = _check_for_updates(config)
    for line in update_messages:
        sys.stderr.write(f"{line}\n")

    if args.extract_from_report:
        out_dir = args.extract_dir or os.path.dirname(os.path.abspath(args.extract_from_report)) or "."
        extracted = _extract_from_report_file(args.extract_from_report, out_dir)
        sys.stderr.write(f"Extracted {extracted} attachment(s) to {out_dir}\n")
        return 0
    eml_paths = _collect_eml_paths(
        args.eml,
        args.dir,
        recursive=args.recursive,
        includes=args.include,
        excludes=args.exclude,
    )
    if not eml_paths:
        return 0

    output_dir = _resolve_output_dir(args.dir, args.json, args.html)
    if output_dir:
        import os

        os.makedirs(output_dir, exist_ok=True)

    if not args.json and not args.html:
        args.json = True
        args.html = True

    total = len(eml_paths)
    start_time = _monotonic()
    all_reports: list[dict[str, object]] = []
    for index, eml_path in enumerate(eml_paths, start=1):
        if args.dir or total > 1:
            eta = _estimate_eta(start_time, index - 1, total)
            eta_text = f", eta {eta}" if eta else ""
            sys.stderr.write(f"[{index}/{total}] Analyzing {eml_path}{eta_text}\n")
        case_bundle_info = None
        if args.case_bundle:
            case_bundle_info = _prepare_case_bundle(eml_path, args.case_bundle, total)
            from .log_utils import set_log_file

            set_log_file(case_bundle_info["log_path"])
            for line in update_messages:
                _append_case_log(case_bundle_info["log_path"], line)
            _append_case_log(case_bundle_info["log_path"], f"START analyzing {eml_path}")
            extract_dir = case_bundle_info["extract_dir"] if args.extract_attachments else None
        else:
            extract_dir = None
            if args.extract_attachments:
                extract_dir = args.extract_dir or _default_extract_dir(eml_path)
        try:
            report = analyzer.analyze_path(
                eml_path,
                extract_dir=extract_dir,
                enable_enrichments=not args.skip_enrichments,
                enable_macro_analysis=not args.skip_macros,
                embed_attachments=args.embed_attachments,
            )
        except Exception as exc:
            if debug:
                import traceback

                traceback.print_exc()
            else:
                sys.stderr.write(f"Error analyzing {eml_path}: {exc}\n")
            if case_bundle_info:
                _append_case_log(case_bundle_info["log_path"], f"ERROR analyzing {eml_path}: {exc}")
                bundle_path = _finalize_case_bundle(case_bundle_info, eml_path)
                sys.stderr.write(f"Case bundle created (with errors): {bundle_path}\n")
            continue
        output = analyzer.report_as_dict(report)
        all_reports.append(output)
        show_score_details = args.score_details or config.report_score_details
        if not show_score_details:
            output.get("statistics", {}).pop("risk_breakdown", None)

        if args.json:
            if case_bundle_info:
                json_path = case_bundle_info["json_path"]
            else:
                json_path = _resolve_output_path(eml_path, args.json, ".json", output_dir)
            serialized = json.dumps(output, indent=2)
            with open(json_path, "w", encoding="utf-8") as handle:
                handle.write(serialized)
        elif not args.html and len(eml_paths) == 1:
            serialized = json.dumps(output, indent=2)
            sys.stdout.write(serialized + "\n")

        if args.html:
            theme = "dark" if (args.dark or config.report_dark) else "light"
            score_details = args.score_details or config.report_score_details
            theme_overrides = _load_theme_overrides(config.report_theme_file, theme)
            defang_urls = args.defang_urls or config.report_defang_urls
            html_report = build_html_report(
                output,
                theme=theme,
                show_score_details=score_details,
                theme_overrides=theme_overrides,
                defang_urls=defang_urls,
            )
            if case_bundle_info:
                html_path = case_bundle_info["html_path"]
            else:
                html_path = _resolve_output_path(eml_path, args.html, ".html", output_dir)
            with open(html_path, "w", encoding="utf-8") as handle:
                handle.write(html_report)
        if case_bundle_info:
            _append_case_log(case_bundle_info["log_path"], f"DONE analyzing {eml_path}")
            bundle_path = _finalize_case_bundle(case_bundle_info, eml_path)
            sys.stderr.write(f"Case bundle created: {bundle_path}\n")

    if output_dir and total > 1 and not args.case_bundle:
        correlation = build_correlation(all_reports)
        if args.json:
            corr_path = _resolve_correlation_path(output_dir, ".json")
            with open(corr_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(correlation, indent=2))
        if args.html:
            corr_path = _resolve_correlation_path(output_dir, ".html")
            with open(corr_path, "w", encoding="utf-8") as handle:
                handle.write(build_correlation_html(correlation))
    return 0


def _resolve_output_path(
    eml_path: str, arg_value: object, extension: str, output_dir: str | None = None
) -> str:
    if isinstance(arg_value, str):
        return arg_value
    base, _ = _split_eml_path(eml_path)
    filename = f"{base}-report{extension}"
    if output_dir:
        import os

        return os.path.join(output_dir, os.path.basename(filename))
    return filename


def _default_extract_dir(eml_path: str) -> str:
    _, directory = _split_eml_path(eml_path)
    return directory


def _split_eml_path(eml_path: str) -> tuple[str, str]:
    import os

    directory = os.path.dirname(eml_path) or "."
    filename = os.path.basename(eml_path)
    stem, _ = os.path.splitext(filename)
    return os.path.join(directory, stem), directory


def _collect_eml_paths(
    eml_path: str | None,
    directory: str | None,
    recursive: bool = False,
    includes: list[str] | None = None,
    excludes: list[str] | None = None,
) -> list[str]:
    import os
    import fnmatch

    if eml_path:
        return [eml_path]
    if not directory:
        return []
    if not os.path.isdir(directory):
        return []
    include_patterns = includes or []
    exclude_patterns = excludes or []
    if not include_patterns:
        include_patterns = ["*.eml"]

    entries: list[str] = []
    if recursive:
        for root, _, files in os.walk(directory):
            for name in files:
                if _match_patterns(name, include_patterns, exclude_patterns):
                    entries.append(os.path.join(root, name))
    else:
        for name in os.listdir(directory):
            if _match_patterns(name, include_patterns, exclude_patterns):
                entries.append(os.path.join(directory, name))
    return sorted(entries)


def _match_patterns(name: str, includes: list[str], excludes: list[str]) -> bool:
    import fnmatch

    if not any(fnmatch.fnmatch(name, pattern) for pattern in includes):
        return False
    if any(fnmatch.fnmatch(name, pattern) for pattern in excludes):
        return False
    return True


def _resolve_output_dir(dir_value: str | None, json_value: object, html_value: object) -> str | None:
    if not dir_value:
        return None
    if isinstance(json_value, str):
        return json_value
    if isinstance(html_value, str):
        return html_value
    import os

    return os.path.join(dir_value, "output")


def _load_theme_overrides(path: str | None, theme: str) -> dict[str, str] | None:
    if not path:
        return None
    import json
    import os

    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if theme in data and isinstance(data[theme], dict):
        return {str(k): str(v) for k, v in data[theme].items()}
    return {str(k): str(v) for k, v in data.items()}


def _resolve_correlation_path(output_dir: str, extension: str) -> str:
    import os

    return os.path.join(output_dir, f"correlation-report{extension}")


def _prepare_case_bundle(eml_path: str, case_bundle_value: object, total: int) -> dict[str, str]:
    eml_abs = os.path.abspath(eml_path)
    eml_dir = os.path.dirname(eml_abs) or "."
    eml_name = os.path.basename(eml_abs)
    stem, _ = os.path.splitext(eml_name)

    if isinstance(case_bundle_value, str) and case_bundle_value.lower().endswith(".zip") and total == 1:
        zip_path = os.path.abspath(case_bundle_value)
        root_dir = os.path.splitext(zip_path)[0]
    else:
        base_dir = eml_dir
        if isinstance(case_bundle_value, str):
            base_dir = os.path.abspath(case_bundle_value)
        root_dir = os.path.join(base_dir, f"{stem}-case")
        zip_path = os.path.join(base_dir, f"{stem}-case.zip")

    artifacts_dir = os.path.join(root_dir, "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)
    return {
        "root_dir": root_dir,
        "extract_dir": artifacts_dir,
        "log_path": os.path.join(root_dir, "run.log"),
        "json_path": os.path.join(root_dir, f"{stem}-report.json"),
        "html_path": os.path.join(root_dir, f"{stem}-report.html"),
        "zip_path": zip_path,
    }


def _finalize_case_bundle(case_bundle_info: dict[str, str], eml_path: str) -> str:
    root_dir = case_bundle_info["root_dir"]
    zip_path = case_bundle_info["zip_path"]
    os.makedirs(os.path.dirname(zip_path) or ".", exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for current_root, _, files in os.walk(root_dir):
            for name in files:
                full_path = os.path.join(current_root, name)
                arcname = os.path.relpath(full_path, root_dir)
                zf.write(full_path, arcname)
        if os.path.isfile(eml_path):
            zf.write(eml_path, os.path.join("source", os.path.basename(eml_path)))
    return zip_path


def _append_case_log(path: str, message: str) -> None:
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"[{stamp}] {message}\n")
    except OSError:
        return


def _check_for_updates(config: AnalyzerConfig) -> list[str]:
    messages: list[str] = []
    if not config.update_check:
        messages.append("[update] Check disabled (UPDATE_CHECK=false)")
        return messages
    local_sha = _git_output("rev-parse", "HEAD")
    if not local_sha:
        messages.append("[update] Skipped: not a git working tree")
        return messages
    branch = _git_output("rev-parse", "--abbrev-ref", "HEAD") or "main"
    repo = (config.github_repo or "").strip()
    if not repo or "/" not in repo:
        messages.append("[update] Skipped: invalid GITHUB_REPO value")
        return messages
    timeout_seconds = max(1, int(config.update_check_timeout_seconds))
    messages.append(
        f"[update] Checking {repo}@{branch} (timeout={timeout_seconds}s)"
    )
    url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    try:
        response = requests.get(
            url,
            timeout=timeout_seconds,
            headers={"Accept": "application/vnd.github+json"},
        )
    except requests.RequestException as exc:
        messages.append(f"[update] Skipped: network/API error ({exc.__class__.__name__})")
        return messages
    if response.status_code >= 400:
        messages.append(
            f"[update] Skipped: GitHub API returned {response.status_code} {response.reason}"
        )
        return messages
    try:
        payload = response.json()
    except ValueError:
        messages.append("[update] Skipped: invalid GitHub API response")
        return messages
    remote_sha = str(payload.get("sha") or "").strip()
    if not remote_sha:
        messages.append("[update] Skipped: remote commit SHA missing")
        return messages
    if remote_sha == local_sha:
        messages.append(f"[update] Up to date ({local_sha[:10]})")
        return messages
    short_local = local_sha[:10]
    short_remote = remote_sha[:10]
    messages.append(
        f"[update] Newer upstream commit found for {repo}: local {short_local}, remote {short_remote}"
    )
    messages.append(f"[update] Run: git pull origin {branch}")
    return messages


def _git_output(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(Path.cwd()),
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return (result.stdout or "").strip()


def _monotonic() -> float:
    import time

    return time.monotonic()


def _estimate_eta(start: float, completed: int, total: int) -> str:
    if completed <= 0:
        return ""
    elapsed = _monotonic() - start
    avg = elapsed / completed
    remaining = int(max((total - completed) * avg, 0))
    minutes, seconds = divmod(remaining, 60)
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _extract_from_report_file(report_path: str, out_dir: str) -> int:
    with open(report_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    root = data.get("root") if isinstance(data, dict) else None
    if not isinstance(root, dict):
        return 0
    os.makedirs(out_dir, exist_ok=True)
    return _extract_from_message_dict(root, out_dir, prefix="root")


def _extract_from_message_dict(message: dict[str, object], out_dir: str, prefix: str) -> int:
    count = 0
    attachments = message.get("attachments")
    if isinstance(attachments, list):
        for index, item in enumerate(attachments, start=1):
            if not isinstance(item, dict):
                continue
            payload_b64 = item.get("embedded_payload_b64")
            if isinstance(payload_b64, str) and payload_b64:
                try:
                    payload = base64.b64decode(payload_b64)
                except Exception:
                    payload = b""
                if payload:
                    name = item.get("filename")
                    if not isinstance(name, str) or not name.strip():
                        name = f"{prefix}-attachment-{index}.bin"
                    safe_name = _safe_filename(name)
                    final_path = _dedupe_path(os.path.join(out_dir, safe_name))
                    with open(final_path, "wb") as handle:
                        handle.write(payload)
                    count += 1
            nested = item.get("nested_eml")
            if isinstance(nested, dict):
                count += _extract_from_message_dict(nested, out_dir, prefix=f"{prefix}-a{index}")
    return count


def _safe_filename(name: str) -> str:
    cleaned = []
    for ch in name:
        if ch.isalnum() or ch in {".", "_", "-"}:
            cleaned.append(ch)
        else:
            cleaned.append("_")
    safe = "".join(cleaned).strip("._")
    return safe[:180] if safe else "attachment.bin"


def _dedupe_path(path: str) -> str:
    base, ext = os.path.splitext(path)
    if not os.path.exists(path):
        return path
    idx = 1
    while True:
        candidate = f"{base}_{idx}{ext}"
        if not os.path.exists(candidate):
            return candidate
        idx += 1


if __name__ == "__main__":
    raise SystemExit(main())
