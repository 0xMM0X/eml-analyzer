"""IP extraction helpers."""

import ipaddress
import re


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips_from_text(text: str) -> list[str]:
    candidates = set(_IPV4_RE.findall(text))
    valid: list[str] = []
    for item in candidates:
        try:
            ip = ipaddress.ip_address(item)
        except ValueError:
            continue
        if ip.is_global:
            valid.append(item)
    return valid
