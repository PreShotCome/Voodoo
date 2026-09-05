import sqlite3

from voodoo.core.ledger import EventLedger


def test_ledger_verifies_and_detects_tampering(tmp_path):
    ledger = EventLedger(tmp_path / "events.db")
    ledger.append("one", {"value": 1})
    ledger.append("two", {"value": 2})
    assert ledger.verify() == (True, None)

    with sqlite3.connect(ledger.path) as db:
        db.execute("UPDATE events SET payload = ? WHERE sequence = 1", ('{"value":9}',))
    assert ledger.verify() == (False, 1)
