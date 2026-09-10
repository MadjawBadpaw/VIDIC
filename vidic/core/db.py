# Database Module (Phase 4)
#
# SQLite persistence for investigation history. Separate file from
# vidic_cache.db, which is just the IOC threat-intel lookup cache -
# this one is the permanent, user-visible investigation history.

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = 'vidic_history.db'


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                sender TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                analysis_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                label TEXT DEFAULT ''
            )
        ''')
        conn.commit()

        cols = [row[1] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()]
        if 'label' not in cols:
            conn.execute("ALTER TABLE analyses ADD COLUMN label TEXT DEFAULT ''")
            conn.commit()
    finally:
        conn.close()


def save_analysis(subject, sender, verdict, risk_score, analysis_data):
    init_db()
    conn = _connect()
    try:
        cursor = conn.execute(
            'INSERT INTO analyses (subject, sender, verdict, risk_score, analysis_json, created_at, label) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (subject, sender, verdict, risk_score, json.dumps(analysis_data),
             datetime.now(timezone.utc).isoformat(), ''),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_all_analyses():
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            'SELECT id, subject, sender, verdict, risk_score, created_at, label FROM analyses ORDER BY created_at DESC'
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def search_analyses(query):
    init_db()
    conn = _connect()
    try:
        like = f'%{query}%'
        rows = conn.execute(
            'SELECT id, subject, sender, verdict, risk_score, created_at, label FROM analyses '
            'WHERE subject LIKE ? OR sender LIKE ? OR verdict LIKE ? OR label LIKE ? ORDER BY created_at DESC',
            (like, like, like, like),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_analysis_by_id(analysis_id):
    init_db()
    conn = _connect()
    try:
        row = conn.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result['analysis_json'] = json.loads(result['analysis_json'])
        return result
    finally:
        conn.close()


def rename_analysis(analysis_id, new_label):
    init_db()
    conn = _connect()
    try:
        conn.execute('UPDATE analyses SET label = ? WHERE id = ?', (new_label, analysis_id))
        conn.commit()
    finally:
        conn.close()


def delete_analyses_older_than(days):
    init_db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = _connect()
    try:
        cursor = conn.execute('DELETE FROM analyses WHERE created_at < ?', (cutoff,))
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def delete_analysis(analysis_id):
    init_db()
    conn = _connect()
    try:
        conn.execute('DELETE FROM analyses WHERE id = ?', (analysis_id,))
        conn.commit()
    finally:
        conn.close()