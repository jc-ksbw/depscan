@echo off
REM Double-click this file to open depscan in your browser.
cd /d "%~dp0"

REM `&&` is evaluated at runtime. Testing %errorlevel% inside a parenthesised
REM block would not work here: cmd expands it when the block is parsed, so the
REM fallback would read a stale value.
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"

if not defined PY (
    echo Python 3.11 or newer is required but was not found.
    echo.
    echo Install it from https://www.python.org/downloads/ and tick
    echo "Add python.exe to PATH" during setup, then run this again.
    echo.
    pause
    exit /b 1
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 (
    echo depscan needs Python 3.11 or newer. The version found is:
    %PY% --version
    echo.
    echo Install a newer Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Starting depscan. Keep this window open while you use it.
echo Close this window, or press Ctrl+C, to stop.
echo.
%PY% -m depscan gui
pause
