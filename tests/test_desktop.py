import sys
from pathlib import Path

from voodoo.desktop import CommandRunner


def test_desktop_runner_uses_argument_list_without_shell(tmp_path):
    runner = CommandRunner(tmp_path, lambda _: None)
    value = "host; Remove-Item C:\\*"
    command = runner.command("scan", "scope", value, "--ports", "443")
    assert command[:3] == [sys.executable, "-u", "-m"]
    assert command[-3:] == [value, "--ports", "443"]
    assert isinstance(command, list)


def test_windows_launcher_uses_absolute_project_paths():
    launcher = (Path(__file__).parents[1] / "Voodoo-Desktop.cmd").read_text()
    assert "%~dp0scripts\\setup.ps1" in launcher
    assert "%~dp0.venv\\Scripts\\pythonw.exe" in launcher
    assert "if errorlevel 1 (" in launcher
    assert "launcher is separated from the Voodoo project" in launcher


def test_setup_script_is_independent_of_current_directory():
    setup = (Path(__file__).parents[1] / "scripts" / "setup.ps1").read_text()
    assert "$projectRoot = Split-Path -Parent $PSScriptRoot" in setup
    assert 'Join-Path $projectRoot ".venv"' in setup
    assert '"${projectRoot}[dev]"' in setup
