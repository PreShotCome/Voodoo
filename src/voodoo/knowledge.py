from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KnowledgeHit:
    title: str
    content: str
    source: str
    kind: str


class KnowledgeBase:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self._connect() as db:
            db.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS documents USING fts5(title, content, source, kind)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def add(
        self,
        title: str,
        content: str,
        source: str = "operator",
        kind: str = "full_text",
    ) -> None:
        if kind not in {"full_text", "index_pointer"}:
            raise ValueError("kind must be full_text or index_pointer")
        with self._connect() as db:
            db.execute(
                "INSERT INTO documents VALUES (?, ?, ?, ?)",
                (title, content, source, kind),
            )

    def search(self, query: str, limit: int = 5) -> list[KnowledgeHit]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT title, content, source, kind FROM documents WHERE documents MATCH ? ORDER BY rank LIMIT ?",
                (query, limit),
            ).fetchall()
        return [KnowledgeHit(*row) for row in rows]

    def count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT count(*) FROM documents").fetchone()[0])
