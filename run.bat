@echo off
setlocal EnableExtensions
title ScamShield AI - Portable Launcher

REM Always work from the folder where this BAT file is located.
set "APP_DIR=%~dp0"
cd /d "%APP_DIR%"

echo ============================================================
echo                  SCAMSHIELD AI
echo              Portable Project Launcher
echo ============================================================
echo.
echo Project folder:
echo %APP_DIR%
echo.

REM Make sure the project files are beside this BAT file.
if not exist "%APP_DIR%app.py" (
    echo [ERROR] app.py was not found beside run.bat.
    echo Please keep run.bat inside the ScamShield project folder.
    echo.
    pause
    exit /b 1
)

if not exist "%APP_DIR%requirements.txt" (
    echo [ERROR] requirements.txt was not found beside run.bat.
    echo.
    echo Expected file:
    echo %APP_DIR%requirements.txt
    echo.
    echo Please extract the COMPLETE ZIP folder before running run.bat.
    echo Do not move run.bat by itself.
    echo.
    pause
    exit /b 1
)

REM Find Python launcher first, then python.exe.
where py >nul 2>nul
if %errorlevel%==0 (
    set "PY=py"
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        set "PY=python"
    ) else (
        echo [ERROR] Python 3.10+ was not found.
        echo Install Python from https://www.python.org/downloads/
        echo Make sure "Add Python to PATH" is enabled.
        echo.
        pause
        exit /b 1
    )
)

echo [1/4] Checking Python version...
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 3.10 or newer is required.
    pause
    exit /b 1
)

REM Use a project-local virtual environment.
set "VENV=%APP_DIR%.venv"
set "VENV_PY=%VENV%\Scripts\python.exe"

echo.
echo [2/4] Preparing virtual environment...
if not exist "%VENV_PY%" (
    %PY% -m venv "%VENV%"
    if errorlevel 1 (
        echo [ERROR] Could not create the virtual environment.
        pause
        exit /b 1
    )
)

echo.
echo [3/4] Installing required packages...
"%VENV_PY%" -m pip install --disable-pip-version-check -r "%APP_DIR%requirements.txt"
if errorlevel 1 (
    echo.
    echo [ERROR] Package installation failed.
    echo Check your internet connection and try again.
    pause
    exit /b 1
)

echo.
echo [4/4] Starting ScamShield AI...
echo.
echo Browser: http://127.0.0.1:5000
echo Admin:   http://127.0.0.1:5000/admin/login
echo.
echo Keep this window open while using the application.
echo Close it to stop the server.
echo.

start "" "http://127.0.0.1:5000"
"%VENV_PY%" "%APP_DIR%app.py"

echo.
echo ScamShield AI has stopped.
pause
