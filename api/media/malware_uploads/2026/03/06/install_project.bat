@echo off
setlocal enabledelayedexpansion

:: Check Python version (require 3.6 <= version < 3.12)
for /f "tokens=2 delims= " %%i in ('python --version 2^>^&1') do set PY_VERSION=%%i
for /f "tokens=1,2 delims=." %%a in ("!PY_VERSION!") do (
    set "PY_MAJOR=%%a"
    set "PY_MINOR=%%b"
)

if %PY_MAJOR% LSS 3 (
    echo Python 3.6 or higher is required.
    exit /b 1
) 
if %PY_MAJOR% EQU 3 (
    if %PY_MINOR% LSS 6 (
        echo Python 3.6 or higher is required.
        exit /b 1
    )
    if %PY_MINOR% GEQ 12 (
        echo Python version must be less than 3.12.
        exit /b 1
    )
)
if %PY_MAJOR% GTR 3 (
    echo Python version must be less than 3.12.
    exit /b 1
)

:: Check Node.js version (require >= 18.0)
for /f "tokens=1 delims=v." %%i in ('node -v') do set "NODE_MAJOR=%%i"
if !NODE_MAJOR! LSS 18 (
    echo Node.js version 18 or higher is required.
    exit /b 1
)

:: Set PowerShell Execution Policy if needed to avoid activation issues
powershell -Command "try { .\venv\Scripts\activate } catch { Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force }"

:: Check if virtual environment exists, and create if it doesn't
if not exist ".\venv\Scripts\activate" (
    echo Creating virtual environment...
    python.exe -m venv venv
)

:: Attempt to activate the virtual environment
call .\venv\Scripts\activate || (
    echo Failed to activate virtual environment. Ensure PowerShell execution policy allows script running.
    exit /b 1
)

echo Upgrading pip and installing dependencies...
python.exe -m pip install -U pip
pip install -r .\requirements.txt

cd api
python.exe .\manage.py makemigrations
python.exe .\manage.py migrate

:: Delay to ensure backend setup completes
timeout /t 5 /nobreak >nul

endlocal
