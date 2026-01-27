"""URL extraction helpers."""

import re
from typing import Any
from urllib.parse import urlparse, parse_qs, unquote
from html.parser import HTMLParser


_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.anchor_texts: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)
                self._current_href = value
                self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a":
            return
        if self._current_href is not None:
            text = "".join(self._current_text).strip()
            if text:
                self.anchor_texts.append((self._current_href, text))
        self._current_href = None
        self._current_text = []


def extract_urls_from_text(text: str) -> list[str]:
    return list({match.group(0) for match in _URL_RE.finditer(text)})


def extract_urls_from_html(html: str) -> list[str]:
    parser = _LinkParser()
    parser.feed(html)
    urls = set(parser.links)
    urls.update(_URL_RE.findall(html))
    return [item for item in urls if _is_http_url(item)]


def extract_anchor_pairs(html: str) -> list[tuple[str, str]]:
    parser = _LinkParser()
    parser.feed(html)
    pairs = []
    for href, text in parser.anchor_texts:
        pairs.append((href, text))
    return pairs


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attrs_dict = {name.lower(): (value or "") for name, value in attrs}
        if tag_lower == "form":
            self._current = {
                "action": attrs_dict.get("action", ""),
                "method": (attrs_dict.get("method") or "get").lower(),
                "inputs": [],
            }
            return
        if self._current is None:
            return
        if tag_lower == "input":
            entry = {
                "name": attrs_dict.get("name", ""),
                "type": (attrs_dict.get("type") or "text").lower(),
                "value": attrs_dict.get("value", ""),
                "placeholder": attrs_dict.get("placeholder", ""),
                "required": "required" in attrs_dict,
                "autocomplete": attrs_dict.get("autocomplete", ""),
            }
            self._current["inputs"].append(entry)
        elif tag_lower == "textarea":
            entry = {
                "name": attrs_dict.get("name", ""),
                "type": "textarea",
                "placeholder": attrs_dict.get("placeholder", ""),
                "required": "required" in attrs_dict,
                "autocomplete": attrs_dict.get("autocomplete", ""),
            }
            self._current["inputs"].append(entry)
        elif tag_lower == "select":
            entry = {
                "name": attrs_dict.get("name", ""),
                "type": "select",
                "required": "required" in attrs_dict,
            }
            self._current["inputs"].append(entry)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form":
            return
        if self._current is not None:
            self.forms.append(self._current)
        self._current = None


def extract_forms_from_html(html: str) -> list[dict[str, Any]]:
    parser = _FormParser()
    parser.feed(html)
    results: list[dict[str, Any]] = []
    for form in parser.forms:
        inputs = form.get("inputs") or []
        input_types = [item.get("type") or "text" for item in inputs]
        type_counts: dict[str, int] = {}
        for item_type in input_types:
            type_counts[item_type] = type_counts.get(item_type, 0) + 1
        has_password = any(item_type == "password" for item_type in input_types)
        has_file = any(item_type == "file" for item_type in input_types)
        hidden_count = sum(1 for item_type in input_types if item_type == "hidden")
        action = form.get("action") or ""
        external_action = _is_http_url(action)
        results.append(
            {
                "action": action,
                "method": form.get("method") or "get",
                "inputs": inputs,
                "input_types": type_counts,
                "input_count": len(inputs),
                "has_password": has_password,
                "has_file": has_file,
                "hidden_count": hidden_count,
                "external_action": external_action,
            }
        )
    return results


def maybe_defang(url: str, enabled: bool) -> str:
    if not enabled:
        return url
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return defanged.replace(".", "[.]")


def detect_rewritten_url(url: str) -> dict[str, str] | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.netloc or "").lower()
    if not host:
        return None
    qs = parse_qs(parsed.query)

    if "urldefense.proofpoint.com" in host or "urldefense.com" in host:
        # Proofpoint v2: /v2/url?u=<encoded>
        if parsed.path.startswith("/v2/url") and "u" in qs:
            candidate = _decode_proofpoint(qs.get("u", [""])[0])
            return _build_rewrite("Proofpoint", candidate)
        # Proofpoint v3: /v3/__<url>__;...
        if parsed.path.startswith("/v3/") and "__" in parsed.path:
            candidate = _decode_proofpoint_v3(parsed.path)
            return _build_rewrite("Proofpoint", candidate)

    if "safelinks.protection.outlook.com" in host:
        candidate = qs.get("url", [""])[0]
        return _build_rewrite("Microsoft Safe Links", unquote(candidate))

    if "securelink" in host or "secure-links" in host:
        candidate = qs.get("url", [""])[0]
        return _build_rewrite("SecureLink", unquote(candidate))

    return None


def _build_rewrite(provider: str, candidate: str) -> dict[str, str] | None:
    candidate = candidate.strip()
    if not candidate:
        return None
    if not candidate.startswith("http"):
        candidate = "http://" + candidate
    return {"provider": provider, "original": candidate}


def _decode_proofpoint(value: str) -> str:
    # Proofpoint v2 encoding: url-encoded with '-' representing '%'
    if not value:
        return value
    decoded = value.replace("-", "%")
    decoded = decoded.replace("_", "/")
    return unquote(decoded)


def _decode_proofpoint_v3(path: str) -> str:
    # Example: /v3/__http://example.com__;...
    marker = "__"
    try:
        start = path.index(marker) + len(marker)
        end = path.index(marker, start)
    except ValueError:
        return ""
    return unquote(path[start:end])


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    return bool(parsed.netloc)
