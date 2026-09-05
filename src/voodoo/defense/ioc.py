from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IOCMatch:
    path: str
    indicator: str
    kind: str


class IOCHunter:
    def hunt(
        self, root: Path, hashes: set[str] | None = None, names: set[str] | None = None
    ) -> list[IOCMatch]:
        hashes = {item.lower() for item in (hashes or set())}
        names = {item.lower() for item in (names or set())}
        root = root.expanduser().resolve()
        paths = [root] if root.is_file() else root.rglob("*")
        matches: list[IOCMatch] = []
        for path in paths:
            if not path.is_file():
                continue
            if path.name.lower() in names:
                matches.append(IOCMatch(str(path), path.name, "filename"))
            if hashes:
                try:
                    digest = _sha256(path)
                except OSError:
                    continue
                if digest in hashes:
                    matches.append(IOCMatch(str(path), digest, "sha256"))
        return matches


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
