@echo off
setlocal
set "APP_DIR=%~dp0"
cd /d "%APP_DIR%"
if not exist "%APP_DIR%app.py" (
    echo app.py not found. Keep this BAT inside the ScamShield project folder.
    pause
    exit /b 1
)
if not exist "%APP_DIR%run.bat" (
    echo run.bat not found.
    pause
    exit /b 1
)
call "%APP_DIR%run.bat"
