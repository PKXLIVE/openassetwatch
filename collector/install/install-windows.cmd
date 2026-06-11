@echo off
setlocal

set SCRIPT_DIR=%~dp0

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python "%SCRIPT_DIR%install.py" %*
  exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 "%SCRIPT_DIR%install.py" %*
  exit /b %ERRORLEVEL%
)

echo Python 3.10 or newer is required.
exit /b 1
