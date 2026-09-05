$ErrorActionPreference = "Stop"
$python = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Run scripts/setup.ps1 first."
}

& $python -m pytest -q
& $python -m ruff check .
& $python -m voodoo audit verify

