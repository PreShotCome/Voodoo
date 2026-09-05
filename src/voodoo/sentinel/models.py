from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class Signal:
    rule: str
    severity: str
    source_ip: str | None
    excerpt: str
    occurred_at: str

    @classmethod
    def now(
        cls, rule: str, severity: str, source_ip: str | None, excerpt: str
    ) -> "Signal":
        return cls(
            rule, severity, source_ip, excerpt[:240], datetime.now(UTC).isoformat()
        )


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    source_ip: str | None
    rule: str
    count: int
