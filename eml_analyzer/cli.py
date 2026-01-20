"""CLI entrypoint for EML Analyzer."""

import argparse
import json
import sys

from .analyzer import EmlAnalyzer
from .config import AnalyzerConfig
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
        "--dark",
        action="store_true",
        help="Generate a dark mode HTML report.",
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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.eml and not args.dir:
        parser.error("Either -f/--file or -d/--dir is required.")

    config = AnalyzerConfig.from_env()
    analyzer = EmlAnalyzer(config, verbose=args.verbose)
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

    total = len(eml_paths)
    start_time = _monotonic()
    for index, eml_path in enumerate(eml_paths, start=1):
        if args.dir or total > 1:
            eta = _estimate_eta(start_time, index - 1, total)
            eta_text = f", eta {eta}" if eta else ""
            sys.stderr.write(f"[{index}/{total}] Analyzing {eml_path}{eta_text}\n")
        extract_dir = None
        if args.extract_attachments:
            extract_dir = args.extract_dir or _default_extract_dir(eml_path)
        report = analyzer.analyze_path(eml_path, extract_dir=extract_dir)
        output = analyzer.report_as_dict(report)
        show_score_details = args.score_details or config.report_score_details
        if not show_score_details:
            output.get("statistics", {}).pop("risk_breakdown", None)

        if args.json:
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
            html_report = build_html_report(output, theme=theme, show_score_details=score_details)
            html_path = _resolve_output_path(eml_path, args.html, ".html", output_dir)
            with open(html_path, "w", encoding="utf-8") as handle:
                handle.write(html_report)
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


if __name__ == "__main__":
    raise SystemExit(main())
