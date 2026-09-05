from voodoo.core.ledger import EventLedger
from voodoo.sentinel import Correlator, Detector, SentinelGuard


def test_high_confidence_web_probe_is_immediately_blocked(tmp_path):
    detector = Detector()
    signal = detector.inspect_http("/.env", {}, "8.8.8.8")[0]
    decision = Correlator().evaluate(signal, "block")
    final = SentinelGuard(EventLedger(tmp_path / "events.db")).enforce(signal, decision)
    assert final.action == "block"
    assert final.reason == "high-confidence attack signature"


def test_repeated_authentication_failures_correlate(tmp_path):
    detector = Detector()
    correlator = Correlator(threshold=3, window_seconds=60)
    guard = SentinelGuard(EventLedger(tmp_path / "events.db"))
    actions = []
    for _ in range(3):
        signal = detector.inspect_line("Failed password for root from 8.8.8.8")[0]
        actions.append(
            guard.enforce(signal, correlator.evaluate(signal, "block")).action
        )
    assert actions == ["alert", "alert", "block"]


def test_private_sources_are_protected_from_automatic_containment(tmp_path):
    detector = Detector()
    signal = detector.inspect_http("/../../etc/passwd", {}, "192.168.1.4")[0]
    decision = Correlator().evaluate(signal, "divert")
    final = SentinelGuard(EventLedger(tmp_path / "events.db")).enforce(signal, decision)
    assert final.action == "alert"
    assert "suppressed" in final.reason
