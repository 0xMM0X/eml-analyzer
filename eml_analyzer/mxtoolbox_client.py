"""MxToolbox API client."""

from dataclasses import dataclass
from typing import Any

import requests

from .log_utils import log_debug

@dataclass
class MxToolboxClient:
    api_key: str
    timeout_seconds: int = 20
    debug: bool = False

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        if not domain:
            return {"status": "skipped", "reason": "empty_domain"}
        url = f"https://api.mxtoolbox.com/api/v1/lookup/mx/{domain}"
        headers = {
            "Authorization": self.api_key,
            "x-api-key": self.api_key,
            "User-Agent": "eml-analyzer",
        }
        try:
            log_debug(self.debug, f"MxToolbox request domain={domain}")
            response = requests.get(url, headers=headers, timeout=self.timeout_seconds)
        except requests.RequestException as exc:
            log_debug(self.debug, f"MxToolbox error domain={domain} exc={exc}")
            return {"status": "error", "error": str(exc)}

        if response.status_code >= 400:
            log_debug(self.debug, f"MxToolbox error domain={domain} status={response.status_code}")
            return {
                "status": "error",
                "error": f"{response.status_code} {response.reason}",
                "body": _safe_json(response),
            }

        log_debug(self.debug, f"MxToolbox ok domain={domain} status={response.status_code}")
        return {"status": "ok", "data": _safe_json(response)}


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
