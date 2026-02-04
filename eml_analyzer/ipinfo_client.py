"""IP geo/ASN enrichment client (ipinfo.io)."""

from dataclasses import dataclass
from typing import Any

import requests

from .log_utils import log_debug

@dataclass
class IpInfoClient:
    api_key: str | None = None
    timeout_seconds: int = 20
    debug: bool = False

    def lookup(self, ip: str) -> dict[str, Any]:
        url = f"https://ipinfo.io/{ip}/json"
        params = {}
        if self.api_key:
            params["token"] = self.api_key
        try:
            log_debug(self.debug, f"ipinfo request ip={ip}")
            response = requests.get(url, params=params, timeout=self.timeout_seconds)
        except requests.RequestException as exc:
            log_debug(self.debug, f"ipinfo error ip={ip} exc={exc}")
            return {"status": "error", "error": str(exc)}
        if response.status_code >= 400:
            log_debug(self.debug, f"ipinfo error ip={ip} status={response.status_code}")
            return {
                "status": "error",
                "error": f"{response.status_code} {response.reason}",
                "body": _safe_json(response),
            }
        log_debug(self.debug, f"ipinfo ok ip={ip} status={response.status_code}")
        return {"status": "ok", "data": _safe_json(response)}


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
