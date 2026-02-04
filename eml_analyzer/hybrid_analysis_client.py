"""Hybrid Analysis public lookup client."""

from dataclasses import dataclass
from typing import Any

import requests

from .log_utils import log_debug

@dataclass
class HybridAnalysisClient:
    api_key: str
    timeout_seconds: int = 20
    debug: bool = False

    def lookup_hash(self, sha256: str) -> dict[str, Any]:
        if not sha256 or not sha256.strip():
            return {"status": "skipped", "reason": "empty_hash"}
        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            "api-key": self.api_key,
            "user-agent": "eml-analyzer",
        }
        params = {"hash": sha256}
        try:
            log_debug(self.debug, f"Hybrid search hash={file_hash}")
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            log_debug(self.debug, f"Hybrid error hash={file_hash} exc={exc}")
            return {"status": "error", "error": str(exc)}

        if response.status_code >= 400:
            log_debug(self.debug, f"Hybrid error hash={file_hash} status={response.status_code}")
            return {
                "status": "error",
                "error": f"{response.status_code} {response.reason}",
                "body": _safe_json(response),
            }

        log_debug(self.debug, f"Hybrid ok hash={file_hash} status={response.status_code}")
        return {"status": "ok", "data": _safe_json(response)}


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
