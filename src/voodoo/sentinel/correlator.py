from __future__ import annotations

from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from voodoo.sentinel.models import Decision, Signal


class Correlator:
    def __init__(self, threshold: int = 6, window_seconds: int = 60):
        if threshold < 2 or window_seconds < 5:
            raise ValueError("unsafe correlation settings")
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._events: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)

    def evaluate(self, signal: Signal, mode: str) -> Decision:
        if signal.source_ip is None:
            return Decision(
                "alert", "signal has no attributable source", None, signal.rule, 1
            )
        now = datetime.fromisoformat(signal.occurred_at).astimezone(UTC)
        key = (signal.source_ip, signal.rule)
        events = self._events[key]
        events.append(now)
        cutoff = now - self.window
        while events and events[0] < cutoff:
            events.popleft()
        count = len(events)
        immediate = signal.rule in {
            "web-traversal",
            "web-secret-probe",
            "web-injection",
            "suspicious-command",
        }
        if count < self.threshold and not immediate:
            return Decision(
                "alert",
                "correlation threshold not reached",
                signal.source_ip,
                signal.rule,
                count,
            )
        action = mode if mode in {"block", "divert"} else "alert"
        reason = (
            "high-confidence attack signature"
            if immediate
            else f"{count} matching signals inside correlation window"
        )
        return Decision(action, reason, signal.source_ip, signal.rule, count)
