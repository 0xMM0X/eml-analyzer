"""Urlscan.io API client."""

from dataclasses import dataclass
import time
from typing import Any
from urllib.parse import urlparse

import requests


@dataclass
class UrlscanClient:
    api_key: str
    timeout_seconds: int = 20
    poll_attempts: int = 8
    poll_delay_seconds: int = 3
    visibility: str = "private"  # <-- CHANGED (public|unlisted typically work; private often doesn't)

    def scan_url(self, url: str) -> dict[str, Any]:
        if not _is_http_url(url):
            return {"status": "skipped", "reason": "unsupported_url"}

        submit = self._post_scan(url)
        if submit.get("status") != "ok":
            return submit

        data = submit.get("data") or {}
        api_url = data.get("api")
        uuid = data.get("uuid")

        if not api_url and uuid:
            api_url = f"https://urlscan.io/api/v1/result/{uuid}/"
        if not api_url:
            return {"status": "pending", "submission": data, "note": "missing_api_url"}

        return self._poll_result(api_url, data)

    def _headers(self) -> dict[str, str]:
        return {
            "API-Key": self.api_key,
            "Accept": "application/json",
            # Optional but sometimes helps with picky proxies/WAFs:
            "User-Agent": "UrlscanClient/1.0",
        }

    def _post_scan(self, url: str) -> dict[str, Any]:
        endpoint = "https://urlscan.io/api/v1/scan/"

        # NOTE: "private" often requires a paid plan / special key
        payload = {"url": url, "visibility": self.visibility}

        try:
            response = requests.post(
                endpoint,
                headers=self._headers(),
                json=payload,  # <-- CHANGED
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            return {"status": "error", "error": str(exc)}

        if response.status_code >= 400:
            body = _safe_json(response)
            return {
                "status": "error",
                "error": f"{response.status_code} {response.reason}",
                "body": body,  # <-- this will typically say exactly why (e.g., visibility not allowed)
                "submitted_payload": payload,
            }

        return {"status": "ok", "data": _safe_json(response)}

    def _poll_result(self, api_url: str, submission: dict[str, Any] | None) -> dict[str, Any]:
        attempts = max(1, self.poll_attempts)

        for attempt in range(attempts):
            try:
                response = requests.get(
                    api_url,
                    headers=self._headers(),
                    timeout=self.timeout_seconds,
                )
            except requests.RequestException as exc:
                return {"status": "error", "error": str(exc)}

            if response.status_code == 200:
                return {"status": "ok", "data": _safe_json(response)}

            # urlscan commonly returns 404 while the result is still being processed.
            # 429 = rate limited. 425 may happen depending on infra.
            if response.status_code in {404, 425, 429}:
                if attempt < attempts - 1:
                    time.sleep(self.poll_delay_seconds)
                    continue
                return {
                    "status": "pending",
                    "submission": submission,
                    "note": f"{response.status_code} {response.reason}",
                    "api_url": api_url,
                }

            return {
                "status": "error",
                "error": f"{response.status_code} {response.reason}",
                "body": _safe_json(response),
                "api_url": api_url,
            }

        return {
            "status": "pending",
            "submission": submission,
            "note": "poll_attempts_exhausted",
            "api_url": api_url,
        }


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
