@echo off
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "SCRIPT=%~dp0KSVPN-uninstall.ps1"
if not exist "%SCRIPT%" (
  echo KSVPN-uninstall.ps1 not found next to this file.
  echo Please keep both files in the same folder.
  pause
  exit /b 1
)
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
exit /b %errorlevel%
