
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
    conn.execute('PRAGMA foreign_keys = ON')
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

        conn.execute('''
            CREATE TABLE IF NOT EXISTS ioc_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                UNIQUE(type, value)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS email_ioc_edges (
                analysis_id INTEGER NOT NULL,
                ioc_id INTEGER NOT NULL,
                PRIMARY KEY (analysis_id, ioc_id),
                FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
                FOREIGN KEY (ioc_id) REFERENCES ioc_nodes(id) ON DELETE CASCADE
            )
        ''')
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
        analysis_id = cursor.lastrowid
        conn.commit()

        iocs = analysis_data.get('iocs', [])
        _record_ioc_edges(conn, analysis_id, iocs)

        return analysis_id
    finally:
        conn.close()


def _record_ioc_edges(conn, analysis_id, iocs):
    """Links an analysis to every IOC it contained, creating ioc_nodes
    rows as needed. Called from save_analysis - iocs is the same list
    of {'type': ..., 'value': ..., 'source': ...} dicts already stored
    in analysis_json, so this adds no new extraction work."""
    for ioc in iocs:
        ioc_type = ioc.get('type')
        ioc_value = ioc.get('value')
        if not ioc_type or not ioc_value:
            continue

        conn.execute(
            'INSERT OR IGNORE INTO ioc_nodes (type, value) VALUES (?, ?)',
            (ioc_type, ioc_value),
        )
        row = conn.execute(
            'SELECT id FROM ioc_nodes WHERE type = ? AND value = ?',
            (ioc_type, ioc_value),
        ).fetchone()
        if row is None:
            continue
        ioc_id = row[0]

        conn.execute(
            'INSERT OR IGNORE INTO email_ioc_edges (analysis_id, ioc_id) VALUES (?, ?)',
            (analysis_id, ioc_id),
        )
    conn.commit()


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


def get_ioc_graph_data():
    """Returns the raw rows needed to build the IOC relationship graph:
    every analysis (id, subject/label, verdict, risk_score) and every
    (analysis_id, ioc_type, ioc_value) edge. Consumed by
    vidic.core.graph, kept here so all SQL stays in this module."""
    init_db()
    conn = _connect()
    try:
        analyses = conn.execute(
            'SELECT id, subject, verdict, risk_score, label FROM analyses'
        ).fetchall()
        edges = conn.execute('''
            SELECT e.analysis_id, n.type, n.value
            FROM email_ioc_edges e
            JOIN ioc_nodes n ON n.id = e.ioc_id
        ''').fetchall()
        return [dict(row) for row in analyses], [dict(row) for row in edges]
    finally:
        conn.close()