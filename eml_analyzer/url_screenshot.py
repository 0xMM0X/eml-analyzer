"""URL screenshot helper (optional Playwright)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import base64

try:
    from playwright.sync_api import sync_playwright  # type: ignore
except Exception:  # pragma: no cover
    sync_playwright = None


@dataclass
class UrlScreenshotter:
    timeout_ms: int = 20000

    def capture(self, url: str) -> dict[str, Any]:
        if sync_playwright is None:
            return {"status": "missing", "error": "playwright not installed"}
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
                page.set_viewport_size({"width": 1280, "height": 720})
                image_bytes = page.screenshot(full_page=True)
                browser.close()
            encoded = base64.b64encode(image_bytes).decode("ascii")
            return {"status": "ok", "data": encoded, "mime": "image/png"}
        except Exception as exc:  # pragma: no cover
            return {"status": "error", "error": str(exc)}
