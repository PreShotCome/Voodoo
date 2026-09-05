from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Drift:
    path: str
    status: str
    expected: str | None
    actual: str | None


class IntegrityMonitor:
    """HMAC-authenticated file baselines with deterministic drift reports."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = state_dir / "integrity.key"
        self.manifest_path = state_dir / "integrity.json"

    def create(self, roots: list[Path]) -> int:
        resolved_roots = [path.expanduser().resolve() for path in roots]
        files = _inventory(resolved_roots)
        payload = {
            "version": 1,
            "roots": [str(path) for path in resolved_roots],
            "files": files,
        }
        key = self._key()
        payload["signature"] = _sign(payload, key)
        self.manifest_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return len(files)

    def check(self) -> list[Drift]:
        if not self.manifest_path.exists():
            raise RuntimeError("no integrity baseline exists")
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        signature = payload.pop("signature", "")
        if not hmac.compare_digest(signature, _sign(payload, self._key())):
            raise RuntimeError("integrity baseline signature is invalid")
        expected: dict[str, str] = payload["files"]
        actual = _inventory([Path(item) for item in payload.get("roots", [])])
        result: list[Drift] = []
        for path in sorted(set(expected) | set(actual)):
            if path not in actual:
                result.append(Drift(path, "deleted", expected[path], None))
            elif path not in expected:
                result.append(Drift(path, "created", None, actual[path]))
            elif expected[path] != actual[path]:
                result.append(Drift(path, "modified", expected[path], actual[path]))
        return result

    def _key(self) -> bytes:
        if not self.key_path.exists():
            self.key_path.write_bytes(secrets.token_bytes(32))
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:
                pass
        return self.key_path.read_bytes()


def _inventory(roots: list[Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    for root in roots:
        root = root.expanduser().resolve()
        candidates = (
            [root]
            if root.is_file()
            else sorted(path for path in root.rglob("*") if path.is_file())
        )
        for path in candidates:
            try:
                result[str(path)] = _hash_file(path)
            except (OSError, PermissionError):
                continue
    return result


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sign(payload: dict[str, object], key: bytes) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, raw, hashlib.sha256).hexdigest()
