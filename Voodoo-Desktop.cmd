@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo Voodoo is not installed yet. Running setup...
  powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\setup.ps1"
  if errorlevel 1 pause & exit /b 1
)
start "Voodoo" ".venv\Scripts\pythonw.exe" -m voodoo.desktop
