"""URL extraction helpers."""

import re
from urllib.parse import urlparse
from html.parser import HTMLParser


_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)


def extract_urls_from_text(text: str) -> list[str]:
    return list({match.group(0) for match in _URL_RE.finditer(text)})


def extract_urls_from_html(html: str) -> list[str]:
    parser = _LinkParser()
    parser.feed(html)
    urls = set(parser.links)
    urls.update(_URL_RE.findall(html))
    return [item for item in urls if _is_http_url(item)]


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    return bool(parsed.netloc)
