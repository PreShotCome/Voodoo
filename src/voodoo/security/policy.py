from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

from voodoo.core.ledger import EventLedger
from voodoo.security.scope import EngagementScope
from voodoo.security.vpn import ProtonVPNGuard


class PolicyDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class Lease:
    lease_id: str
    scope_name: str
    capability: str
    reason: str
    issued_at: str
    expires_at: str

    @property
    def active(self) -> bool:
        return datetime.fromisoformat(self.expires_at) > datetime.now(UTC)


class PolicyEngine:
    """Requires a declared scope and short-lived capability lease for active work."""

    def __init__(self, ledger: EventLedger, vpn: ProtonVPNGuard | None = None):
        self.ledger = ledger
        self.vpn = vpn or ProtonVPNGuard()

    def save_scope(self, scope: EngagementScope) -> None:
        self.ledger.append("scope.created", asdict(scope))

    def scopes(self) -> dict[str, EngagementScope]:
        result: dict[str, EngagementScope] = {}
        for event in self.ledger.events("scope.created"):
            value = event.payload
            result[value["name"]] = EngagementScope(
                value["name"],
                tuple(value.get("domains", ())),
                tuple(value.get("networks", ())),
                bool(value.get("require_proton", False)),
            )
        return result

    def grant(
        self, scope_name: str, capability: str, minutes: int, reason: str
    ) -> Lease:
        if scope_name not in self.scopes():
            raise ValueError(f"unknown scope: {scope_name}")
        if not 1 <= minutes <= 120:
            raise ValueError("lease duration must be between 1 and 120 minutes")
        if len(reason.strip()) < 8:
            raise ValueError("give a meaningful authorization reason")
        now = datetime.now(UTC)
        lease = Lease(
            secrets.token_hex(8),
            scope_name,
            capability,
            reason.strip(),
            now.isoformat(),
            (now + timedelta(minutes=minutes)).isoformat(),
        )
        self.ledger.append("lease.granted", asdict(lease))
        return lease

    def revoke(self, lease_id: str, reason: str) -> None:
        self.ledger.append("lease.revoked", {"lease_id": lease_id, "reason": reason})

    def active_leases(self) -> list[Lease]:
        revoked = {e.payload["lease_id"] for e in self.ledger.events("lease.revoked")}
        leases = [Lease(**e.payload) for e in self.ledger.events("lease.granted")]
        return [
            lease for lease in leases if lease.lease_id not in revoked and lease.active
        ]

    def authorize(self, scope_name: str, capability: str, target: str) -> Lease:
        scope = self.scopes().get(scope_name)
        if scope is None:
            self._deny(scope_name, capability, target, "unknown scope")
        if not scope.permits(target):
            self._deny(
                scope_name, capability, target, "target outside engagement scope"
            )
        if scope.require_proton:
            try:
                vpn_state = self.vpn.require()
            except RuntimeError as exc:
                self._deny(scope_name, capability, target, str(exc))
            self.ledger.append("vpn.verified", vpn_state.as_dict())
        lease = next(
            (
                item
                for item in self.active_leases()
                if item.scope_name == scope_name and item.capability == capability
            ),
            None,
        )
        if lease is None:
            self._deny(scope_name, capability, target, "no active capability lease")
        self.ledger.append(
            "action.authorized",
            {
                "scope": scope_name,
                "capability": capability,
                "target": target,
                "lease_id": lease.lease_id,
            },
        )
        return lease

    def _deny(self, scope: str, capability: str, target: str, reason: str):
        self.ledger.append(
            "action.denied",
            {
                "scope": scope,
                "capability": capability,
                "target": target,
                "reason": reason,
            },
        )
        raise PolicyDenied(reason)

    def describe(self) -> str:
        return json.dumps(
            {
                "scopes": list(self.scopes()),
                "active_leases": [asdict(x) for x in self.active_leases()],
            },
            indent=2,
        )
