$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Run scripts/setup.ps1 first."
}

& $python -m pytest -q $projectRoot
& $python -m ruff check $projectRoot
& $python -m voodoo audit verify
