"""Hashing utilities."""

import hashlib
from dataclasses import dataclass


@dataclass
class HashResult:
    md5: str
    sha1: str
    sha256: str
    size: int


def hash_bytes(data: bytes) -> HashResult:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    md5.update(data)
    sha1.update(data)
    sha256.update(data)

    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size=len(data),
    )
