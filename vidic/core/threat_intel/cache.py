# IOC lookup cache (Phase 3)
#
# SQLite-backed cache shared by every threat_intel client. Avoids
# redundant calls and lets free-tier rate limits survive across runs.

from __future__ import annotations

import json
import sqlite3
import time

DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24 hours


class IOCCache:
    def __init__(self, db_path='vidic_cache.db', default_ttl_seconds=DEFAULT_TTL_SECONDS):
        self.db_path = db_path
        self.default_ttl_seconds = default_ttl_seconds
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ioc_cache (
                    indicator TEXT NOT NULL,
                    type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    checked_at REAL NOT NULL,
                    PRIMARY KEY (indicator, type, source)
                )
            ''')
            conn.commit()
        finally:
            conn.close()

    def get(self, indicator, type_, source, ttl_seconds=None):
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                'SELECT result_json, checked_at FROM ioc_cache WHERE indicator=? AND type=? AND source=?',
                (indicator, type_, source),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return None

        result_json, checked_at = row
        if time.time() - checked_at > ttl:
            return None
        return json.loads(result_json)

    def set(self, indicator, type_, source, result):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                'INSERT OR REPLACE INTO ioc_cache (indicator, type, source, result_json, checked_at) '
                'VALUES (?, ?, ?, ?, ?)',
                (indicator, type_, source, json.dumps(result), time.time()),
            )
            conn.commit()
        finally:
            conn.close()