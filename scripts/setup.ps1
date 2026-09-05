$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.12 or newer is required."
}

$version = python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
if ([version]$version -lt [version]"3.12") {
    throw "Python 3.12 or newer is required; found $version."
}

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
& .\.venv\Scripts\python.exe -m voodoo init
& "$PSScriptRoot\install-desktop.ps1"
Write-Host "Voodoo is installed. Open the Voodoo shortcut on your desktop."
