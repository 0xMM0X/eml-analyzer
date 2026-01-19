"""Office attachment analysis helpers."""

from __future__ import annotations

import base64
import io
import re
import zipfile
from typing import Any

try:
    import olefile
except ImportError:  # pragma: no cover
    olefile = None

try:
    from oletools.olevba import VBA_Parser
except ImportError:  # pragma: no cover
    VBA_Parser = None

_OFFICE_EXTENSIONS = {
    ".docx",
    ".xlsx",
    ".pptx",
    ".docm",
    ".xlsm",
    ".pptm",
}


def analyze_office_attachment(filename: str | None, payload: bytes) -> dict[str, Any] | None:
    if not filename or not payload:
        return None

    lower = filename.lower()
    if not any(lower.endswith(ext) for ext in _OFFICE_EXTENSIONS):
        return None

    if not _is_zip(payload):
        return None

    tool_results: list[dict[str, Any]] = []
    macro_modules_all: list[dict[str, Any]] = []

    macro_modules_olevba = _extract_with_olevba(payload)
    if VBA_Parser is None:
        tool_results.append({"tool": "oletools (olevba)", "status": "missing"})
    else:
        tool_results.append(
            {
                "tool": "oletools (olevba)",
                "status": "ok" if macro_modules_olevba else "no_macros",
                "modules": macro_modules_olevba,
                "summaries": _summarize_modules(macro_modules_olevba),
            }
        )
        macro_modules_all.extend(macro_modules_olevba)

    vba_data = None
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names = set(zf.namelist())
        vba_name = _find_vba_project(names)
        if vba_name:
            vba_data = zf.read(vba_name)

    if olefile is None:
        tool_results.append({"tool": "olefile (custom)", "status": "missing"})
    elif not vba_data:
        tool_results.append({"tool": "olefile (custom)", "status": "no_vba_project"})
    else:
        macro_modules_olefile = _extract_vba_modules(vba_data)
        tool_results.append(
            {
                "tool": "olefile (custom)",
                "status": "ok" if macro_modules_olefile else "no_modules",
                "modules": macro_modules_olefile,
                "summaries": _summarize_modules(macro_modules_olefile),
            }
        )
        macro_modules_all.extend(macro_modules_olefile)

    macro_names = _names_from_modules(macro_modules_all)
    string_hits: list[str] = []
    if vba_data:
        strings = _extract_printable_strings(vba_data)
        if not macro_names:
            macro_names = _extract_macro_names(strings)
        string_hits = _macro_string_hits(strings)

    return {
        "office_type": _office_type_from_name(lower),
        "has_macros": bool(macro_modules_all or macro_names),
        "macro_names": macro_names,
        "string_hits": string_hits,
        "macro_modules": macro_modules_all,
        "macro_summaries": _summarize_modules(macro_modules_all),
        "macro_parse": _macro_parse_status_from_results(tool_results),
        "tool_results": tool_results,
    }


def _extract_with_olevba(payload: bytes) -> list[dict[str, Any]]:
    if VBA_Parser is None:
        return []
    modules: list[dict[str, Any]] = []
    try:
        parser = VBA_Parser(filename=None, data=payload)
        if not parser.detect_vba_macros():
            parser.close()
            return []
        for (_, stream_path, vba_filename, vba_code) in parser.extract_all_macros():
            name = vba_filename or stream_path or "module"
            clean_code = _clean_vba_code(vba_code or "", keep_indent=True)
            if clean_code and _is_plausible_vba(clean_code):
                modules.append({"name": name, "code": clean_code})
        parser.close()
    except Exception:
        return []
    return modules


def _is_zip(payload: bytes) -> bool:
    with io.BytesIO(payload) as handle:
        return zipfile.is_zipfile(handle)


def _find_vba_project(names: set[str]) -> str | None:
    for candidate in (
        "word/vbaProject.bin",
        "xl/vbaProject.bin",
        "ppt/vbaProject.bin",
        "vbaProject.bin",
    ):
        if candidate in names:
            return candidate
    return None


def _office_type_from_name(name: str) -> str:
    if name.endswith(".docm"):
        return "docm"
    if name.endswith(".xlsm"):
        return "xlsm"
    if name.endswith(".pptm"):
        return "pptm"
    if name.endswith(".docx"):
        return "docx"
    if name.endswith(".xlsx"):
        return "xlsx"
    if name.endswith(".pptx"):
        return "pptx"
    return "office"


def _extract_printable_strings(data: bytes, min_len: int = 4) -> list[str]:
    text = re.sub(rb"[^\x20-\x7e]", b"\n", data)
    strings = []
    for part in text.splitlines():
        if len(part) >= min_len:
            try:
                strings.append(part.decode("ascii", errors="ignore"))
            except ValueError:
                continue
    return strings


def _extract_macro_names(strings: list[str]) -> list[str]:
    names = set()
    pattern = re.compile(r"\b(Sub|Function)\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
    for item in strings:
        match = pattern.search(item)
        if match:
            names.add(match.group(2))
    return sorted(names)


def _macro_string_hits(strings: list[str]) -> list[str]:
    hits = []
    keywords = ("AutoOpen", "AutoClose", "Workbook_Open", "Document_Open")
    for item in strings:
        for keyword in keywords:
            if keyword.lower() in item.lower():
                hits.append(item)
                break
        if len(hits) >= 10:
            break
    return hits


def _extract_vba_modules(vba_bin: bytes) -> list[dict[str, Any]]:
    if olefile is None:
        return []
    modules: list[dict[str, Any]] = []
    try:
        with olefile.OleFileIO(io.BytesIO(vba_bin)) as ole:
            for path in ole.listdir(streams=True, storages=False):
                if not path or path[0] != "VBA":
                    continue
                name = path[-1]
                if name.lower() in {"dir", "_vba_project"} or name.startswith("__"):
                    continue
                try:
                    data = ole.openstream(path).read()
                except OSError:
                    continue
                raw = _decompress_vba_stream_raw(data)
                decoded = _decode_vba_text(raw)
                clean_code = _clean_vba_code(decoded, keep_indent=True)
                if clean_code and _is_plausible_vba(clean_code):
                    modules.append({"name": name, "code": clean_code})
                elif raw:
                    modules.append(
                        {
                            "name": name,
                            "encoded": _encode_snippet(raw),
                            "encoding": "base64",
                        }
                    )
    except (OSError, ValueError):
        return []
    return modules


def _decompress_vba_stream_raw(data: bytes) -> bytes:
    if not data or data[0] != 0x01:
        return b""
    pos = 1
    output = bytearray()
    while pos + 2 <= len(data):
        header = int.from_bytes(data[pos : pos + 2], "little")
        pos += 2
        chunk_size = (header & 0x0FFF) + 1
        chunk_flag = header & 0x8000
        chunk_end = min(pos + chunk_size, len(data))
        if not chunk_flag:
            output.extend(data[pos:chunk_end])
            pos = chunk_end
            continue

        chunk_start = len(output)
        while pos < chunk_end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if flags & (1 << bit) == 0:
                    output.append(data[pos])
                    pos += 1
                    continue
                if pos + 1 >= chunk_end:
                    pos = chunk_end
                    break
                token = data[pos] | (data[pos + 1] << 8)
                pos += 2
                decompressed_size = len(output) - chunk_start
                max_offset = min(decompressed_size, 0x1000)
                bit_count = 0
                while (1 << bit_count) < max_offset:
                    bit_count += 1
                bit_count = max(bit_count, 1)
                length_mask = (1 << (16 - bit_count)) - 1
                offset_mask = (1 << bit_count) - 1
                offset = (token & offset_mask) + 1
                length = ((token >> bit_count) & length_mask) + 3
                for _ in range(length):
                    if offset > len(output):
                        break
                    output.append(output[-offset])
        pos = chunk_end
    return bytes(output)


def _decode_vba_text(data: bytes) -> str:
    if not data:
        return ""
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            decoded = data.decode(encoding, errors="ignore")
            sanitized = _sanitize_vba_text(decoded)
            if _is_mostly_printable(sanitized):
                return sanitized
        except ValueError:
            continue
    return ""


def _sanitize_vba_text(text: str) -> str:
    cleaned = []
    for ch in text:
        if ch.isprintable() or ch in {"\n", "\r", "\t"}:
            cleaned.append(ch)
    return "".join(cleaned).strip()


def _is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in {"\n", "\r", "\t"})
    ratio = printable / max(len(text), 1)
    return ratio >= 0.8


def _is_plausible_vba(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    if "attribute vb_name" in lowered:
        return True
    if "sub " in lowered or "function " in lowered:
        return True
    if "end sub" in lowered or "end function" in lowered:
        return True
    return False


def _clean_vba_code(text: str, keep_indent: bool = False) -> str:
    if not text:
        return ""
    lines = []
    for line in text.splitlines():
        raw = line.rstrip("\r")
        stripped = raw.strip()
        if not stripped:
            continue
        if not any(ch.isalpha() for ch in stripped):
            continue
        if sum(1 for ch in stripped if ch.isprintable()) / max(len(stripped), 1) < 0.9:
            continue
        lines.append(raw if keep_indent else stripped)
    return "\n".join(lines).strip()


def _encode_snippet(data: bytes, limit: int = 2048) -> str:
    snippet = data[:limit]
    encoded = base64.b64encode(snippet).decode("ascii")
    if len(data) > limit:
        encoded += "...(truncated)"
    return encoded


def _names_from_modules(modules: list[dict[str, Any]]) -> list[str]:
    names = []
    for module in modules:
        name = module.get("name")
        if name:
            names.append(name)
    return sorted(set(names))


def _macro_parse_status() -> str:
    if olefile is None:
        return "olefile_missing"
    return "no_modules"


def _macro_parse_status_from_results(results: list[dict[str, Any]]) -> str:
    for item in results:
        if item.get("tool") == "oletools (olevba)" and item.get("status") == "ok":
            return "olevba"
    for item in results:
        if item.get("tool") == "olefile (custom)" and item.get("status") == "ok":
            return "olefile"
    return "no_modules"


def _summarize_modules(modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    keywords = {
        "createobject",
        "wscript",
        "shell",
        "powershell",
        "cmd.exe",
        "http",
        "https",
        "xmlhttp",
        "adodb.stream",
        "base64",
        "autoopen",
        "document_open",
        "workbook_open",
    }
    for module in modules:
        code = module.get("code") or ""
        lines = [line for line in code.splitlines() if line.strip()]
        lower_code = code.lower()
        hits = [kw for kw in keywords if kw in lower_code]
        summaries.append(
            {
                "name": module.get("name"),
                "line_count": len(lines),
                "keyword_hits": sorted(hits),
                "preview": "\n".join(lines[:8]),
            }
        )
    return summaries
