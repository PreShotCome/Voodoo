import hashlib

from voodoo.defense.ioc import IOCHunter
from voodoo.defense.secrets import SecretScanner
from voodoo.defense.triage import LogTriage


def test_secret_scanner_redacts_value(tmp_path):
    source = tmp_path / "config.py"
    secret = "this-is-a-very-secret-value"
    source.write_text(f'api_key = "{secret}"\n')
    findings = SecretScanner().scan(tmp_path)
    assert len(findings) == 1
    assert secret not in findings[0].preview


def test_ioc_hunter_matches_hash_and_name(tmp_path):
    sample = tmp_path / "odd.bin"
    sample.write_bytes(b"sample")
    digest = hashlib.sha256(b"sample").hexdigest()
    matches = IOCHunter().hunt(tmp_path, {digest}, {"odd.bin"})
    assert {item.kind for item in matches} == {"sha256", "filename"}


def test_log_triage_returns_structured_signals(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Failed password for invalid user root from 192.0.2.3\n")
    report = LogTriage().analyze(log)
    assert report["signal_count"] == 1
    assert report["rules"] == {"authentication-bruteforce": 1}
