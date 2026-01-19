"""VirusTotal API client."""

import base64
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class VirusTotalClient:
    api_key: str
    timeout_seconds: int = 20
    allow_url_submission: bool = False
    max_requests_per_minute: int = 4

    def __post_init__(self) -> None:
        self._request_times: deque[float] = deque()

    def get_file_report(self, file_hash: str) -> dict[str, Any]:
        return self._get(f"/files/{file_hash}")

    def get_url_report(self, url: str) -> dict[str, Any]:
        url_id = self._encode_url_id(url)
        response = self._get(f"/urls/{url_id}")
        if response.get("status") == "not_found" and self.allow_url_submission:
            submit = self._post("/urls", data={"url": url})
            return {
                "status": "submitted",
                "submission": submit,
            }
        return response

    def _get(self, path: str) -> dict[str, Any]:
        return self._request("GET", path)

    def _post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, data=data)

    def _request(self, method: str, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        self._throttle()
        url = f"https://www.virustotal.com/api/v3{path}"
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                data=data,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            return {"status": "error", "error": str(exc)}

        if response.status_code == 404:
            return {"status": "not_found"}

        if response.status_code >= 400:
            return {
                "status": "error",
                "error": f"{response.status_code} {response.reason}",
                "body": _safe_json(response),
            }

        return {
            "status": "ok",
            "data": _safe_json(response),
        }

    def _throttle(self) -> None:
        if self.max_requests_per_minute <= 0:
            return
        now = time.monotonic()
        window = 60.0
        while self._request_times and now - self._request_times[0] >= window:
            self._request_times.popleft()
        if len(self._request_times) >= self.max_requests_per_minute:
            sleep_for = window - (now - self._request_times[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
            now = time.monotonic()
            while self._request_times and now - self._request_times[0] >= window:
                self._request_times.popleft()
        self._request_times.append(time.monotonic())

    @staticmethod
    def _encode_url_id(url: str) -> str:
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=")


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
