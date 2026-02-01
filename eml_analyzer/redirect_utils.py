"""Server-side redirect resolution."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import requests


def resolve_redirect_chain(
    url: str,
    timeout_seconds: int = 10,
    max_hops: int = 5,
) -> dict[str, Any]:
    session = requests.Session()
    headers = {"User-Agent": "EMLAnalyzer/1.0"}
    chain: list[dict[str, Any]] = []
    current = url
    error = None

    for _ in range(max_hops):
        try:
            response = _request_no_redirect(
                session, current, timeout_seconds, headers
            )
        except requests.RequestException as exc:
            error = str(exc)
            break

        chain.append({"url": current, "status": response.status_code})
        location = response.headers.get("Location")
        if not location or response.status_code < 300 or response.status_code >= 400:
            break
        current = urljoin(current, location)

    result = {
        "status": "ok" if not error else "error",
        "chain": chain,
        "final_url": chain[-1]["url"] if chain else url,
        "error": error,
    }
    return result


def _request_no_redirect(
    session: requests.Session,
    url: str,
    timeout_seconds: int,
    headers: dict[str, str],
) -> requests.Response:
    try:
        response = session.request(
            "HEAD",
            url,
            allow_redirects=False,
            timeout=timeout_seconds,
            headers=headers,
        )
        if response.status_code in {405, 501}:
            raise requests.RequestException("HEAD not supported")
        return response
    except requests.RequestException:
        return session.request(
            "GET",
            url,
            allow_redirects=False,
            timeout=timeout_seconds,
            headers=headers,
        )
