"""Hybrid Analysis public lookup client."""

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class HybridAnalysisClient:
    api_key: str
    timeout_seconds: int = 20

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

        return {"status": "ok", "data": _safe_json(response)}


def _safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
