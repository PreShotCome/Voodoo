from voodoo.defense.integrity import IntegrityMonitor


def test_integrity_reports_modify_create_delete(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    first = watched / "first.txt"
    deleted = watched / "deleted.txt"
    first.write_text("one")
    deleted.write_text("gone")
    monitor = IntegrityMonitor(tmp_path / "state")
    assert monitor.create([watched]) == 2

    first.write_text("two")
    deleted.unlink()
    (watched / "new.txt").write_text("new")
    drift = {item.status for item in monitor.check()}
    assert drift == {"modified", "created", "deleted"}


def test_integrity_detects_manifest_tampering(tmp_path):
    watched = tmp_path / "file.txt"
    watched.write_text("safe")
    monitor = IntegrityMonitor(tmp_path / "state")
    monitor.create([watched])
    text = monitor.manifest_path.read_text().replace("safe", "unsafe")
    # Make a real payload change because hashes do not include source contents.
    text = text.replace('"version": 1', '"version": 2')
    monitor.manifest_path.write_text(text)
    try:
        monitor.check()
    except RuntimeError as exc:
        assert "signature" in str(exc)
    else:
        raise AssertionError("tampering was accepted")
