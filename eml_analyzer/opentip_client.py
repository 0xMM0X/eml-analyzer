"""Kaspersky OpenTIP API client."""

from dataclasses import dataclass
from typing import Any

import requests

from .log_utils import log_debug

@dataclass
class OpenTipClient:
    api_key: str
    timeout_seconds: int = 20
    debug: bool = False

    def lookup_hash(self, hash_value: str) -> dict[str, Any]:
        return self._lookup("hash", hash_value)

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        return self._lookup("ip", ip)

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        return self._lookup("domain", domain)

    def lookup_url(self, url: str) -> dict[str, Any]:
        return self._lookup("url", url)

    def _lookup(self, endpoint: str, value: str) -> dict[str, Any]:
        url = f"https://opentip.kaspersky.com/api/v1/search/{endpoint}"
        headers = {
            "x-api-key": self.api_key,
            "Accept": "application/json",
        }
        params = {"request": value}
        try:
            log_debug(self.debug, f"OpenTIP request {endpoint} value={value}")
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            log_debug(self.debug, f"OpenTIP error {endpoint} value={value} exc={exc}")
            return {"status": "error", "error": str(exc)}

        if response.status_code >= 400:
            log_debug(self.debug, f"OpenTIP error {endpoint} value={value} status={response.status_code}")
            return {
                "status": "error",
                "error": f"{response.status_code} {response.reason}",
                "body": _safe_json(response),
            }

        log_debug(self.debug, f"OpenTIP ok {endpoint} value={value} status={response.status_code}")
        return {
            "status": "ok",
            "data": _safe_json(response),
        }


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
