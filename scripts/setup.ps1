$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvRoot = Join-Path $projectRoot ".venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.12 or newer is required."
}

$version = python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
if ([version]$version -lt [version]"3.12") {
    throw "Python 3.12 or newer is required; found $version."
}

if (-not (Test-Path $venvPython)) {
    python -m venv $venvRoot
}

& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -e "${projectRoot}[dev]"
& $venvPython -m voodoo init
& "$PSScriptRoot\install-desktop.ps1"
Write-Host "Voodoo is installed. Open the Voodoo shortcut on your desktop."
