from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class LogSignal:
    severity: str
    rule: str
    line: int
    excerpt: str


PATTERNS = (
    (
        "high",
        "authentication-bruteforce",
        re.compile(r"(?i)(failed password|login failed|invalid user)"),
    ),
    (
        "high",
        "privilege-change",
        re.compile(
            r"(?i)(added to administrators|sudo:.*command=|special privileges assigned)"
        ),
    ),
    (
        "critical",
        "security-control-disabled",
        re.compile(r"(?i)(antivirus.*disabled|firewall.*disabled|audit.*cleared)"),
    ),
    (
        "medium",
        "suspicious-encoding",
        re.compile(r"(?i)(powershell.+-enc(?:odedcommand)?|frombase64string)"),
    ),
    (
        "medium",
        "web-probe",
        re.compile(r"(?i)(\.\./|/wp-admin|/\.env|/etc/passwd|union\s+select)"),
    ),
)


class LogTriage:
    def analyze(self, path: Path, max_lines: int = 250_000) -> dict[str, object]:
        signals: list[LogSignal] = []
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                if number > max_lines:
                    break
                for severity, rule, pattern in PATTERNS:
                    if pattern.search(line):
                        signals.append(
                            LogSignal(severity, rule, number, line.strip()[:240])
                        )
        counts = Counter(signal.rule for signal in signals)
        return {
            "file": str(path.resolve()),
            "signal_count": len(signals),
            "rules": dict(counts),
            "signals": [asdict(signal) for signal in signals[:500]],
            "truncated": len(signals) > 500,
        }
