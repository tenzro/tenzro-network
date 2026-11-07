@echo off
rem Runs the Tenzro hardware check (check only; changes nothing).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\tenzro-check.ps1" %*
exit /b %ERRORLEVEL%
