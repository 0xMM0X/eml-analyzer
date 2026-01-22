"""PDF attachment analysis helpers (peepdf optional)."""

from __future__ import annotations

import os
import re
import sys
import tempfile
import shutil
import subprocess
import zlib
from pathlib import Path
from urllib.request import urlretrieve
from typing import Any

try:
    from peepdf.peepdf import PDFParser  # type: ignore
except Exception:  # pragma: no cover
    PDFParser = None


_PDF_MAGIC = b"%PDF"


def analyze_pdf_attachment(filename: str | None, payload: bytes) -> dict[str, Any] | None:
    if not payload:
        return None
    if not _is_pdf(filename, payload):
        return None
    heuristics = _scan_pdf_tokens(payload)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as handle:
            handle.write(payload)
            tmp_path = handle.name

        pdfid = _run_pdfid(tmp_path)
        pdf_parser = _run_pdf_parser(tmp_path)

        if PDFParser is None:
            return {
                "status": "missing",
                "tool": "peepdf",
                "heuristics": heuristics,
                "pdfid": pdfid,
                "pdf_parser": pdf_parser,
            }

        parser = PDFParser()
        doc = _parse_with_peepdf(parser, tmp_path)
    except Exception as exc:  # pragma: no cover
        return {
            "status": "error",
            "tool": "peepdf",
            "error": str(exc),
            "heuristics": heuristics,
            "pdfid": pdfid if "pdfid" in locals() else None,
            "pdf_parser": pdf_parser if "pdf_parser" in locals() else None,
        }
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    objects_detail, streams_detail, obj_trunc, stream_trunc = _collect_pdf_details(doc)
    stats = {
        "status": "ok",
        "tool": "peepdf",
        "version": _get_pdf_version(doc),
        "objects": _get_pdf_objects(doc),
        "streams": _get_pdf_streams(doc),
        "heuristics": heuristics,
        "objects_detail": objects_detail,
        "streams_detail": streams_detail,
        "objects_truncated": obj_trunc,
        "streams_truncated": stream_trunc,
        "pdfid": pdfid,
        "pdf_parser": pdf_parser,
    }
    return stats


def _is_pdf(filename: str | None, payload: bytes) -> bool:
    if payload.startswith(_PDF_MAGIC):
        return True
    if filename and filename.lower().endswith(".pdf"):
        return True
    return False


def _scan_pdf_tokens(payload: bytes) -> dict[str, Any]:
    text = payload.decode("latin-1", errors="ignore")
    patterns = {
        "javascript": r"/JavaScript\b",
        "js": r"/JS\b",
        "open_action": r"/OpenAction\b",
        "additional_actions": r"/AA\b",
        "launch": r"/Launch\b",
        "embedded_file": r"/EmbeddedFile\b",
        "embedded_files": r"/EmbeddedFiles\b",
        "filespec": r"/Filespec\b",
    }
    counts: dict[str, int] = {}
    for name, pattern in patterns.items():
        counts[name] = len(re.findall(pattern, text, flags=re.IGNORECASE))
    indicators = [
        f"/JavaScript({counts['javascript']})" if counts["javascript"] else None,
        f"/JS({counts['js']})" if counts["js"] else None,
        f"/OpenAction({counts['open_action']})" if counts["open_action"] else None,
        f"/AA({counts['additional_actions']})" if counts["additional_actions"] else None,
        f"/Launch({counts['launch']})" if counts["launch"] else None,
        f"/EmbeddedFile({counts['embedded_file']})" if counts["embedded_file"] else None,
        f"/EmbeddedFiles({counts['embedded_files']})" if counts["embedded_files"] else None,
        f"/Filespec({counts['filespec']})" if counts["filespec"] else None,
    ]
    indicators = [item for item in indicators if item]
    return {
        "javascript": counts["javascript"] + counts["js"],
        "launch_actions": counts["launch"],
        "embedded_files": counts["embedded_file"] + counts["embedded_files"] + counts["filespec"],
        "indicators": indicators,
    }


def _parse_with_peepdf(parser: Any, path: str) -> Any:
    if hasattr(parser, "parse"):
        result = parser.parse(path)
        if isinstance(result, tuple) and len(result) == 2:
            status, doc = result
            if status not in (0, 1):
                raise RuntimeError(f"peepdf parse error: {status}")
            return doc
        return result
    raise RuntimeError("Unsupported peepdf parser API")


def _get_pdf_version(doc: Any) -> Any:
    if doc is None:
        return None
    if hasattr(doc, "getVersion"):
        try:
            return doc.getVersion()
        except Exception:
            return None
    return getattr(doc, "version", None)


def _get_pdf_objects(doc: Any) -> Any:
    if doc is None:
        return None
    if hasattr(doc, "numObjects"):
        return getattr(doc, "numObjects")
    if hasattr(doc, "getNumObjects"):
        try:
            return doc.getNumObjects()
        except Exception:
            return None
    return None


def _get_pdf_streams(doc: Any) -> Any:
    if doc is None:
        return None
    if hasattr(doc, "numStreams"):
        return getattr(doc, "numStreams")
    if hasattr(doc, "getNumStreams"):
        try:
            return doc.getNumStreams()
        except Exception:
            return None
    return None


def _collect_pdf_details(
    doc: Any, limit: int = 200, stream_preview_limit: int = 4000
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, bool]:
    if doc is None or not hasattr(doc, "getObject") or not hasattr(doc, "maxObjectId"):
        return [], [], False, False
    objects_detail: list[dict[str, Any]] = []
    streams_detail: list[dict[str, Any]] = []
    objects_truncated = False
    streams_truncated = False
    max_id = getattr(doc, "maxObjectId", 0) or 0
    for obj_id in range(1, max_id + 1):
        obj = doc.getObject(obj_id)
        if obj is None:
            continue
        obj_type = obj.__class__.__name__
        is_stream = obj_type == "PDFStream" or hasattr(obj, "rawStream")
        if len(objects_detail) >= limit:
            objects_truncated = True
        else:
            raw_value = None
            if hasattr(obj, "getRawValue"):
                try:
                    raw_value = obj.getRawValue()
                except Exception:
                    raw_value = None
            if raw_value is None and hasattr(obj, "rawValue"):
                raw_value = getattr(obj, "rawValue", None)
            obj_preview, obj_trunc = _preview_stream(raw_value, stream_preview_limit)
            objects_detail.append(
                {
                    "id": obj_id,
                    "type": obj_type,
                    "is_stream": bool(is_stream),
                    "decoded_preview": obj_preview,
                    "decoded_truncated": obj_trunc,
                }
            )
        if is_stream:
            if len(streams_detail) >= limit:
                streams_truncated = True
            else:
                raw_stream = getattr(obj, "rawStream", None)
                decoded_stream = getattr(obj, "decodedStream", None)
                encoded_stream = getattr(obj, "encodedStream", None)
                decoded_preview, decoded_truncated = _preview_stream(
                    decoded_stream, stream_preview_limit
                )
                streams_detail.append(
                    {
                        "id": obj_id,
                        "raw_len": _safe_len(raw_stream),
                        "decoded_len": _safe_len(decoded_stream),
                        "encoded_len": _safe_len(encoded_stream),
                        "is_encoded": bool(getattr(obj, "isEncodedStream", False)),
                        "decoded_preview": decoded_preview,
                        "decoded_truncated": decoded_truncated,
                    }
                )
        if objects_truncated and streams_truncated:
            break
    return objects_detail, streams_detail, objects_truncated, streams_truncated


def _safe_len(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return len(value)
    except TypeError:
        return None


def _preview_stream(value: Any, limit: int) -> tuple[str, bool]:
    if value is None:
        return "", False
    raw_bytes = None
    if isinstance(value, bytes):
        raw_bytes = value
        text = value.decode("latin-1", errors="replace")
    elif isinstance(value, str):
        text = value
        raw_bytes = value.encode("latin-1", errors="replace")
    else:
        try:
            text = str(value)
            raw_bytes = text.encode("latin-1", errors="replace")
        except Exception:
            return "", False
    normalized = _normalize_preview(text, raw_bytes)
    if len(normalized) <= limit:
        return normalized, False
    return normalized[:limit], True


def _normalize_preview(text: str, raw_bytes: bytes | None) -> str:
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    ratio = printable / max(len(text), 1)
    if ratio < 0.65 and raw_bytes is not None:
        decoded = _try_inflate(raw_bytes)
        if decoded:
            return decoded
        return text
    return text


def _try_inflate(raw_bytes: bytes) -> str | None:
    try:
        data = zlib.decompress(raw_bytes)
    except Exception:
        try:
            data = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
        except Exception:
            return None
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return data.decode("latin-1", errors="replace")




def _run_pdfid(path: str) -> dict[str, Any]:
    cmd = _find_tool(["pdfid.py", "pdfid"])
    if cmd:
        return _run_tool([cmd, path], "pdfid")
    if _module_exists("pdfid"):
        return _run_tool([sys.executable, "-m", "pdfid", path], "pdfid")
    return {"status": "missing", "tool": "pdfid"}


def _run_pdf_parser(path: str) -> dict[str, Any]:
    cmd = _find_tool(["pdf-parser.py", "pdf-parser"])
    if cmd:
        return _run_tool([cmd, path], "pdf-parser", max_len=None)
    auto_download = os.getenv("TOOLS_AUTO_DOWNLOAD", "false").lower() in {
        "1",
        "true",
        "yes",
    }
    if auto_download:
        downloaded = _download_pdf_parser()
        if downloaded:
            return _run_tool([sys.executable, downloaded, path], "pdf-parser", max_len=None)
    return {"status": "missing", "tool": "pdf-parser"}


def _find_tool(names: list[str]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _run_tool(cmd: list[str], tool: str, max_len: int | None = 12000) -> dict[str, Any]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except Exception as exc:  # pragma: no cover
        return {"status": "error", "tool": tool, "error": str(exc)}
    output = (result.stdout or "") + (result.stderr or "")
    output = output.strip()
    truncated = False
    if max_len is not None and len(output) > max_len:
        output = output[:max_len]
        truncated = True
    parsed = _parse_pdfid_counts(output) if tool == "pdfid" else None
    return {
        "status": "ok" if result.returncode == 0 else "error",
        "tool": tool,
        "returncode": result.returncode,
        "output": output,
        "truncated": truncated,
        "counts": parsed,
    }


def _parse_pdfid_counts(output: str) -> dict[str, int] | None:
    counts: dict[str, int] = {}
    for line in output.splitlines():
        match = re.match(r"^\s*([^:]+):\s*(\d+)\s*$", line)
        if not match:
            continue
        key = match.group(1).strip().lower().replace(" ", "_")
        try:
            counts[key] = int(match.group(2))
        except ValueError:
            continue
    return counts or None


def _module_exists(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def _download_pdf_parser() -> str | None:
    tools_dir = Path(__file__).resolve().parent / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    dest = tools_dir / "pdf-parser.py"
    url = (
        "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/"
        "pdf-parser.py"
    )
    try:
        urlretrieve(url, dest)
    except Exception:
        return None
    return str(dest)
