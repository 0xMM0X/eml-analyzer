"""AbuseIPDB API client."""

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class AbuseIpdbClient:
    api_key: str
    timeout_seconds: int = 20

    def check_ip(self, ip: str) -> dict[str, Any]:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
        }
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            return {"status": "error", "error": str(exc)}

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


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
