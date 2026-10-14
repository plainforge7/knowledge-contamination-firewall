"""Small, fail-closed SQLite memory store for the v0.5 sandbox."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MEMORY_STATUSES = {"confirmed", "quarantine", "denied"}
SANDBOX_PREFIX = "test-only/"

SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    memory_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('confirmed', 'quarantine', 'denied')),
    content_json TEXT NOT NULL,
    source_ids_json TEXT NOT NULL,
    source_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memories_namespace_status
    ON memories(namespace, status);
CREATE TABLE IF NOT EXISTS memory_events (
    event_id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(memory_id) REFERENCES memories(memory_id)
);
CREATE INDEX IF NOT EXISTS idx_memory_events_memory
    ON memory_events(memory_id, created_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MemoryStore:
    """SQLite-backed memory lifecycle with confirmed-only retrieval."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(SCHEMA)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "MemoryStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _validate_namespace(namespace: str) -> None:
        if not isinstance(namespace, str) or not namespace.startswith(SANDBOX_PREFIX):
            raise ValueError("v0.5 store accepts only test-only namespaces")

    @staticmethod
    def _validate_status(status: str) -> None:
        if status not in MEMORY_STATUSES:
            raise ValueError(f"unsupported memory status: {status}")

    def add(
        self,
        content: dict[str, Any],
        *,
        namespace: str,
        status: str = "quarantine",
        source_ids: list[str] | None = None,
        source_type: str = "unknown",
        memory_id: str | None = None,
    ) -> str:
        self._validate_namespace(namespace)
        self._validate_status(status)
        if not isinstance(content, dict) or not content:
            raise ValueError("memory content must be a non-empty object")
        memory_id = memory_id or f"mem-{uuid.uuid4().hex}"
        timestamp = _now()
        with self.connection:
            self.connection.execute(
                """INSERT INTO memories (
                    memory_id, namespace, status, content_json, source_ids_json,
                    source_type, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    memory_id,
                    namespace,
                    status,
                    json.dumps(content, ensure_ascii=False, sort_keys=True),
                    json.dumps(source_ids or [], ensure_ascii=False),
                    source_type,
                    timestamp,
                    timestamp,
                ),
            )
            self._event(memory_id, "created", None, status, {"source_type": source_type})
        return memory_id

    def transition(self, memory_id: str, status: str, *, reason: str) -> None:
        self._validate_status(status)
        row = self.connection.execute(
            "SELECT status FROM memories WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        if row is None:
            raise KeyError(memory_id)
        old_status = str(row["status"])
        if old_status == status:
            return
        timestamp = _now()
        with self.connection:
            self.connection.execute(
                "UPDATE memories SET status = ?, updated_at = ? WHERE memory_id = ?",
                (status, timestamp, memory_id),
            )
            self._event(memory_id, "status_changed", old_status, status, {"reason": reason})

    def get(self, memory_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM memories WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        return self._decode(row) if row else None

    def search(self, query: str, *, namespace: str) -> list[dict[str, Any]]:
        self._validate_namespace(namespace)
        query = query.strip()
        if not query:
            return []
        rows = self.connection.execute(
            """SELECT * FROM memories
            WHERE namespace = ? AND status = 'confirmed'
              AND content_json LIKE ? ORDER BY updated_at DESC""",
            (namespace, f"%{query}%"),
        ).fetchall()
        return [self._decode(row) for row in rows]

    def events(self, memory_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM memory_events WHERE memory_id = ? ORDER BY created_at",
            (memory_id,),
        ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "memory_id": row["memory_id"],
                "event_type": row["event_type"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "detail": json.loads(row["detail_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def _event(
        self,
        memory_id: str,
        event_type: str,
        from_status: str | None,
        to_status: str | None,
        detail: dict[str, Any],
    ) -> None:
        self.connection.execute(
            """INSERT INTO memory_events (
                event_id, memory_id, event_type, from_status, to_status,
                detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                f"event-{uuid.uuid4().hex}",
                memory_id,
                event_type,
                from_status,
                to_status,
                json.dumps(detail, ensure_ascii=False, sort_keys=True),
                _now(),
            ),
        )

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "memory_id": row["memory_id"],
            "namespace": row["namespace"],
            "status": row["status"],
            "content": json.loads(row["content_json"]),
            "source_ids": json.loads(row["source_ids_json"]),
            "source_type": row["source_type"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
