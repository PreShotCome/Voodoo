import sys

from voodoo.desktop import CommandRunner


def test_desktop_runner_uses_argument_list_without_shell(tmp_path):
    runner = CommandRunner(tmp_path, lambda _: None)
    value = "host; Remove-Item C:\\*"
    command = runner.command("scan", "scope", value, "--ports", "443")
    assert command[:3] == [sys.executable, "-u", "-m"]
    assert command[-3:] == [value, "--ports", "443"]
    assert isinstance(command, list)
