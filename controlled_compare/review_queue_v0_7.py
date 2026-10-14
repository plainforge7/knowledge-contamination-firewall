"""Human review queue over the v0.5 memory lifecycle."""

from __future__ import annotations

from typing import Any


class ReviewQueue:
    def __init__(self, store: Any) -> None:
        self.store = store

    def pending(self, *, namespace: str) -> list[dict[str, Any]]:
        rows = self.store.connection.execute(
            """SELECT * FROM memories
            WHERE namespace = ? AND status = 'quarantine'
            ORDER BY created_at""",
            (namespace,),
        ).fetchall()
        return [self.store._decode(row) for row in rows]

    def approve(self, memory_id: str, *, reviewer: str, reason: str) -> None:
        if not reviewer.strip() or not reason.strip():
            raise ValueError("reviewer and reason are required")
        self.store.transition(
            memory_id,
            "confirmed",
            reason=f"human_approval:{reviewer}:{reason}",
        )

    def reject(self, memory_id: str, *, reviewer: str, reason: str) -> None:
        if not reviewer.strip() or not reason.strip():
            raise ValueError("reviewer and reason are required")
        self.store.transition(
            memory_id,
            "denied",
            reason=f"human_rejection:{reviewer}:{reason}",
        )
