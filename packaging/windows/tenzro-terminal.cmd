@echo off
rem Opens a terminal window for Tenzro. Mode: menu (default), setup, check.
rem Prefers Windows Terminal when present, otherwise a plain console window.
setlocal
set "TZ_ROOT=%~dp0"
set "TZ_MODE=%~1"
if "%TZ_MODE%"=="" set "TZ_MODE=menu"
if /i "%TZ_MODE%"=="inner" goto inner

rem The new window starts in the install folder (no quoting needed to find
rem this script); the inner step then moves to the user profile.
set "TZ_DIR=%TZ_ROOT:~0,-1%"
where wt.exe >nul 2>nul
if %ERRORLEVEL%==0 (
  start "" wt.exe -d "%TZ_DIR%" cmd.exe /k tenzro-terminal.cmd inner %TZ_MODE%
) else (
  start "Tenzro" /D "%TZ_DIR%" cmd.exe /k tenzro-terminal.cmd inner %TZ_MODE%
)
exit /b 0

:inner
set "TZ_MODE=%~2"
cd /d "%USERPROFILE%"
set "PATH=%TZ_ROOT%bin;%PATH%"
if /i "%TZ_MODE%"=="check" goto check
if /i "%TZ_MODE%"=="setup" goto setup
tenzro.exe
goto done

:check
echo Tenzro hardware check
echo This only looks at this machine. It changes nothing and starts nothing.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TZ_ROOT%tenzro-check.ps1"
goto done

:setup
echo Tenzro hardware check
echo This only looks at this machine; it changes nothing and starts nothing.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TZ_ROOT%tenzro-check.ps1"
echo.
echo Open a terminal and run: tenzro   (the first time it walks you through setup)
echo Nothing runs in the background and nothing joins the network until you choose to.
echo.
tenzro.exe
:done
echo.
echo You can type tenzro to open the menu, or close this window.
