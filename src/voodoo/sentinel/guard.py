from __future__ import annotations

import ipaddress
from dataclasses import asdict

from voodoo.core.ledger import EventLedger
from voodoo.sentinel.models import Decision, Signal


class SentinelGuard:
    """Turns signals into audited decisions while protecting trusted address space."""

    def __init__(self, ledger: EventLedger, allow_private: bool = False):
        self.ledger = ledger
        self.allow_private = allow_private

    def enforce(self, signal: Signal, decision: Decision) -> Decision:
        action = decision.action
        reason = decision.reason
        if action in {"block", "divert"} and not self._containable(decision.source_ip):
            action = "alert"
            reason = "containment suppressed for trusted, private, or invalid source"
        final = Decision(
            action, reason, decision.source_ip, decision.rule, decision.count
        )
        self.ledger.append("sentinel.signal", asdict(signal))
        self.ledger.append("sentinel.decision", asdict(final))
        return final

    def _containable(self, source: str | None) -> bool:
        if source is None:
            return False
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            return False
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            return False
        if not self.allow_private and (
            address.is_private or address.is_link_local or address.is_reserved
        ):
            return False
        return True
