@echo off
setlocal
pushd "%~dp0" || (
  echo ERROR: Voodoo could not open its project folder.
  pause
  exit /b 1
)

if not exist "%~dp0scripts\setup.ps1" (
  echo ERROR: This launcher is separated from the Voodoo project.
  echo.
  echo Download and extract the complete Voodoo ZIP, then run
  echo Voodoo-Desktop.cmd from inside the extracted Voodoo folder.
  echo Expected file: %~dp0scripts\setup.ps1
  echo.
  pause
  popd
  exit /b 1
)

if not exist "%~dp0.venv\Scripts\pythonw.exe" (
  echo Voodoo is not installed yet. Running setup...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup.ps1"
  if errorlevel 1 (
    echo.
    echo ERROR: Voodoo setup failed. Review the message above.
    pause
    popd
    exit /b 1
  )
)

if not exist "%~dp0.venv\Scripts\pythonw.exe" (
  echo ERROR: Setup completed without creating Voodoo's Python environment.
  pause
  popd
  exit /b 1
)

start "Voodoo" "%~dp0.venv\Scripts\pythonw.exe" -m voodoo.desktop
popd
