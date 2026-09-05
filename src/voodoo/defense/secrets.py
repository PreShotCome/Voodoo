from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecretFinding:
    path: str
    line: int
    rule: str
    preview: str


RULES = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github-token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{50,255})\b"
    ),
    "generic-secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?([^\s'\"]{12,})"
    ),
}

SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}


class SecretScanner:
    def scan(self, root: Path, max_bytes: int = 2_000_000) -> list[SecretFinding]:
        root = root.expanduser().resolve()
        paths = [root] if root.is_file() else root.rglob("*")
        findings: list[SecretFinding] = []
        for path in paths:
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > max_bytes:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                for rule, pattern in RULES.items():
                    if pattern.search(line):
                        findings.append(
                            SecretFinding(str(path), number, rule, _redact(line))
                        )
        return findings


def _redact(line: str) -> str:
    stripped = line.strip()
    if len(stripped) <= 12:
        return "[redacted]"
    return stripped[:8] + "…[redacted]"
