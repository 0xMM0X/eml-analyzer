"""CLI entrypoint for EML Analyzer."""

import argparse
import json
import sys

from .analyzer import EmlAnalyzer
from .config import AnalyzerConfig
from .reporting import build_html_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze EML files with recursive parsing.")
    parser.add_argument("--eml", required=True, help="Path to the EML file to analyze.")
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

    config = AnalyzerConfig.from_env()
    analyzer = EmlAnalyzer(config, verbose=args.verbose)
    extract_dir = None
    if args.extract_attachments:
        extract_dir = args.extract_dir or _default_extract_dir(args.eml)
    report = analyzer.analyze_path(args.eml, extract_dir=extract_dir)
    output = analyzer.report_as_dict(report)
    if not args.score_details:
        output.get("statistics", {}).pop("risk_breakdown", None)

    if args.json:
        json_path = _resolve_output_path(args.eml, args.json, ".json")
        serialized = json.dumps(output, indent=2)
        with open(json_path, "w", encoding="utf-8") as handle:
            handle.write(serialized)
    elif not args.html:
        serialized = json.dumps(output, indent=2)
        sys.stdout.write(serialized + "\n")

    if args.html:
        theme = "dark" if args.dark else "light"
        html_report = build_html_report(output, theme=theme, show_score_details=args.score_details)
        html_path = _resolve_output_path(args.eml, args.html, ".html")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(html_report)
    return 0


def _resolve_output_path(eml_path: str, arg_value: object, extension: str) -> str:
    if isinstance(arg_value, str):
        return arg_value
    base, _ = _split_eml_path(eml_path)
    return f"{base}-report{extension}"


def _default_extract_dir(eml_path: str) -> str:
    _, directory = _split_eml_path(eml_path)
    return directory


def _split_eml_path(eml_path: str) -> tuple[str, str]:
    import os

    directory = os.path.dirname(eml_path) or "."
    filename = os.path.basename(eml_path)
    stem, _ = os.path.splitext(filename)
    return os.path.join(directory, stem), directory


if __name__ == "__main__":
    raise SystemExit(main())
