$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonw = Join-Path $projectRoot ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $pythonw)) {
    throw "Voodoo's virtual environment was not found. Run scripts/setup.ps1 first."
}

$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "Voodoo.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $pythonw
$shortcut.Arguments = "-m voodoo.desktop"
$shortcut.WorkingDirectory = $projectRoot
$shortcut.Description = "Voodoo defensive security control center"
$shortcut.Save()

Write-Host "Desktop shortcut created: $shortcutPath"
