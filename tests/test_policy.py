from dataclasses import dataclass

import pytest

from voodoo.core.ledger import EventLedger
from voodoo.security import EngagementScope, PolicyDenied, PolicyEngine, VPNState


@dataclass
class FakeVPN:
    connected: bool

    def require(self):
        if not self.connected:
            raise RuntimeError("this scope requires an active Proton VPN tunnel")
        return VPNState(True, "proton", "ProtonVPN", "test")


def test_scope_and_lease_are_both_required(tmp_path):
    policy = PolicyEngine(EventLedger(tmp_path / "events.db"), FakeVPN(True))
    policy.save_scope(EngagementScope("lab", networks=("127.0.0.0/8",)))
    with pytest.raises(PolicyDenied, match="no active"):
        policy.authorize("lab", "recon.scan", "127.0.0.1")
    policy.grant("lab", "recon.scan", 5, "authorized local test")
    assert policy.authorize("lab", "recon.scan", "127.0.0.1").active
    with pytest.raises(PolicyDenied, match="outside"):
        policy.authorize("lab", "recon.scan", "192.0.2.1")


def test_proton_requirement_fails_closed(tmp_path):
    policy = PolicyEngine(EventLedger(tmp_path / "events.db"), FakeVPN(False))
    policy.save_scope(
        EngagementScope("remote", networks=("192.0.2.0/24",), require_proton=True)
    )
    policy.grant("remote", "recon.http", 5, "authorized remote test")
    with pytest.raises(PolicyDenied, match="Proton"):
        policy.authorize("remote", "recon.http", "192.0.2.5")
