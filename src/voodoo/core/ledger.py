from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


@dataclass(frozen=True)
class Event:
    sequence: int
    occurred_at: str
    kind: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(
    sequence: int, occurred_at: str, kind: str, payload: str, previous: str
) -> str:
    material = f"{sequence}\n{occurred_at}\n{kind}\n{payload}\n{previous}".encode()
    return hashlib.sha256(material).hexdigest()


class EventLedger:
    """Append-only SQLite ledger whose records form a SHA-256 hash chain."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def append(self, kind: str, payload: dict[str, Any]) -> Event:
        encoded = _canonical(payload)
        occurred_at = datetime.now(UTC).isoformat()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT sequence, event_hash FROM events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if row is None else int(row[0]) + 1
            previous = GENESIS if row is None else str(row[1])
            event_hash = _digest(sequence, occurred_at, kind, encoded, previous)
            db.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
                (sequence, occurred_at, kind, encoded, previous, event_hash),
            )
        return Event(sequence, occurred_at, kind, payload, previous, event_hash)

    def events(self, kind: str | None = None) -> Iterator[Event]:
        query = "SELECT sequence, occurred_at, kind, payload, previous_hash, event_hash FROM events"
        params: tuple[object, ...] = ()
        if kind:
            query += " WHERE kind = ?"
            params = (kind,)
        query += " ORDER BY sequence"
        with self._connect() as db:
            for row in db.execute(query, params):
                yield Event(row[0], row[1], row[2], json.loads(row[3]), row[4], row[5])

    def verify(self) -> tuple[bool, int | None]:
        previous = GENESIS
        expected_sequence = 1
        for event in self.events():
            encoded = _canonical(event.payload)
            expected_hash = _digest(
                event.sequence, event.occurred_at, event.kind, encoded, previous
            )
            if (
                event.sequence != expected_sequence
                or event.previous_hash != previous
                or event.event_hash != expected_hash
            ):
                return False, event.sequence
            previous = event.event_hash
            expected_sequence += 1
        return True, None
