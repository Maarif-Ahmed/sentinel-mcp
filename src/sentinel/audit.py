"""
Audit log — append-only SQLite store for all Sentinel tool invocations.

Every MCP tool call writes an AuditEvent. The log is local to the developer's
machine and never transmitted externally.

Table schema (single table, append-only):
  id TEXT PRIMARY KEY
  timestamp TEXT          ISO 8601 UTC
  event_type TEXT
  repository_root TEXT
  finding_canonical_id TEXT NULL
  action TEXT
  outcome TEXT            'success' | 'error' | 'skipped'
  metadata_json TEXT      JSON blob
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sentinel.schemas import AuditEvent

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_events (
    id                   TEXT PRIMARY KEY,
    timestamp            TEXT NOT NULL,
    event_type           TEXT NOT NULL,
    repository_root      TEXT NOT NULL,
    finding_canonical_id TEXT,
    action               TEXT NOT NULL,
    outcome              TEXT NOT NULL,
    metadata_json        TEXT NOT NULL DEFAULT '{}'
);
"""

_INSERT = """
INSERT INTO audit_events
    (id, timestamp, event_type, repository_root, finding_canonical_id, action, outcome, metadata_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
"""

_SELECT_RECENT = """
SELECT id, timestamp, event_type, repository_root, finding_canonical_id,
       action, outcome, metadata_json
FROM audit_events
WHERE repository_root = ?
ORDER BY timestamp DESC
LIMIT ?;
"""


class AuditLogger:
    """Thread-safe append-only audit log backed by SQLite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._ensure_table()

    def _ensure_table(self) -> None:
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")  # safe concurrent reads
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def log(self, event: AuditEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                _INSERT,
                (
                    event.id,
                    event.timestamp_iso,
                    event.event_type,
                    event.repository_root,
                    event.finding_canonical_id,
                    event.action,
                    event.outcome,
                    json.dumps(event.metadata),
                ),
            )

    def get_recent(self, repository_root: str, limit: int = 50) -> list[AuditEvent]:
        limit = min(limit, 500)
        with self._connect() as conn:
            rows = conn.execute(_SELECT_RECENT, (repository_root, limit)).fetchall()

        events: list[AuditEvent] = []
        for row in rows:
            (id_, ts, event_type, repo_root, canon_id, action, outcome, meta_json) = row
            events.append(
                AuditEvent(
                    id=id_,
                    event_type=event_type,
                    repository_root=repo_root,
                    finding_canonical_id=canon_id,
                    action=action,
                    outcome=outcome,
                    metadata=json.loads(meta_json),
                )
            )
        return events
