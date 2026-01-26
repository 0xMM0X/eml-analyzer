"""Simple IOC cache using SQLite."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class IocCache:
    path: str
    ttl_seconds: int | None = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ioc_cache ("
            "type TEXT NOT NULL,"
            "value TEXT NOT NULL,"
            "response TEXT NOT NULL,"
            "timestamp INTEGER NOT NULL,"
            "PRIMARY KEY (type, value)"
            ")"
        )
        return conn

    def get(self, ioc_type: str, value: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT response, timestamp FROM ioc_cache WHERE type=? AND value=?",
                (ioc_type, value),
            )
            row = cur.fetchone()
            if not row:
                return None
            response_text, ts = row
            if self.ttl_seconds and (int(time.time()) - int(ts)) > self.ttl_seconds:
                return None
            try:
                return json.loads(response_text)
            except json.JSONDecodeError:
                return None

    def set(self, ioc_type: str, value: str, response: dict[str, Any]) -> None:
        payload = json.dumps(response)
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ioc_cache(type, value, response, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (ioc_type, value, payload, now),
            )
