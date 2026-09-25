@echo off
setlocal EnableDelayedExpansion
title GOT JOED NIDS Server Engine - AIR-GAPPED FAST v3

:: ===================================================
:: GOT JOED Air-Gapped Windows Launcher - FULL OFFLINE
:: Root-Level Execution - Auto Admin -> Install -> Launch
:: ===================================================

:: 1. AUTO RUN AS ADMINISTRATOR
net session >nul 2>&1
if %errorLevel% == 0 goto :adminOK
echo [ADMIN] Requesting admin rights...
powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'" >nul 2>&1
exit /b

:adminOK
:: Set working directory to where this script resides (SCANNER root)
cd /d "%~dp0"
color 0A
echo ===================================================
echo   GOT JOED Air-Gapped Windows Launcher / Server
echo   FULL OFFLINE - Python 3.13 Ready
echo ===================================================
echo.

:: ===================================================
:: PATH CONFIGURATION
:: ===================================================
set "ROOT_DIR=%~dp0"
set "WINDOWS_DIR=%ROOT_DIR%Windows"
set "WHEELS_DIR=%WINDOWS_DIR%\wheels"
set "VENV_DIR=%ROOT_DIR%venv"
set "BACKEND_DIR=%ROOT_DIR%backend"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "PIP_EXE=%VENV_DIR%\Scripts\pip.exe"
set "PYTHON_EXE="

:: ===================================================
:: 2. CHECK & INSTALL PYTHON
:: ===================================================
echo [*] [1/5] Checking Python...

for %%P in (python python3 py) do (
    %%P --version >nul 2>&1
    if !errorlevel! == 0 (
        set "PYTHON_EXE=%%P"
        echo [OK] Python found: %%P
        goto :checkNmap
    )
)

:: Check common paths for Python 3.13
if exist "C:\Program Files\Python313\python.exe" set "PYTHON_EXE=C:\Program Files\Python313\python.exe" & goto :checkNmap
if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PYTHON_EXE=%LocalAppData%\Programs\Python\Python313\python.exe" & goto :checkNmap

echo [WARN] Python not found in PATH or standard directories.
for %%i in ("%WINDOWS_DIR%\python-*.exe") do (
    set "PY_INSTALLER=%%i"
    goto :installPython
)
echo [ERROR] No python installer found in %WINDOWS_DIR%
pause
exit /b 1

:installPython
echo [*] Installing !PY_INSTALLER! silently...
"!PY_INSTALLER!" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1 Include_launcher=1
timeout /t 15 /nobreak >nul
set "PATH=%PATH%;C:\Program Files\Python313\;C:\Program Files\Python313\Scripts\;%LocalAppData%\Programs\Python\Python313\;%LocalAppData%\Programs\Python\Python313\Scripts\"
set "PYTHON_EXE=python"
echo [SUCCESS] Python installed

:checkNmap
:: ===================================================
:: 3. CHECK & INSTALL NMAP
:: ===================================================
echo [*] [2/5] Checking Nmap...
where nmap >nul 2>&1
if !errorlevel! == 0 (
    echo [OK] Nmap found in PATH
    goto :checkVenv
)
if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
    set "PATH=%PATH%;C:\Program Files (x86)\Nmap\"
    echo [OK] Nmap found in Program Files (x86)
    goto :checkVenv
)

echo [WARN] Nmap not found, looking for installer...
for %%i in ("%WINDOWS_DIR%\nmap-*-setup.exe") do (
    set "NMAP_INSTALLER=%%i"
    goto :installNmap
)
echo [WARN] No nmap installer found in %WINDOWS_DIR%, continuing without Nmap...
goto :checkVenv

:installNmap
echo [*] Installing !NMAP_INSTALLER! /S ...
"!NMAP_INSTALLER!" /S
timeout /t 10 /nobreak >nul
set "PATH=%PATH%;C:\Program Files (x86)\Nmap\"
echo [SUCCESS] Nmap installed

:checkVenv
:: ===================================================
:: 4. VIRTUAL ENVIRONMENT & WHEELS
:: ===================================================
echo [*] [3/5] Checking venv in SCANNER folder...
if exist "%VENV_PYTHON%" (
    "%VENV_PYTHON%" -c "import fastapi, uvicorn, nmap" >nul 2>&1
    if !errorlevel! == 0 (
        echo [FAST] Venv ready - skipping pip install
        goto :launch
    )
)

if not exist "%VENV_DIR%" (
    echo [*] Creating venv in %ROOT_DIR%...
    %PYTHON_EXE% -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo [ERROR] venv creation failed
        pause
        exit /b 1
    )
)

echo [*] [4/5] Installing offline wheels...
if not exist "%WHEELS_DIR%\*.whl" (
    color 0C
    echo [ERROR] wheels folder empty or missing in %WINDOWS_DIR%!
    pause
    exit /b 1
)

:: Update core tools first
"%VENV_PYTHON%" -m pip install --no-index --find-links="%WHEELS_DIR%" --upgrade pip setuptools wheel --quiet --disable-pip-version-check >nul 2>&1

:: Install dependencies
"%PIP_EXE%" install --no-index --find-links="%WHEELS_DIR%" fastapi uvicorn python-nmap pydantic --quiet --disable-pip-version-check
if !errorlevel! == 0 (
    echo [SUCCESS] Packages installed from wheels
    goto :verifyInstall
)

color 0C
echo [ERROR] Pip install failed. Check if all required wheels are present.
pause
exit /b 1

:verifyInstall
"%VENV_PYTHON%" -c "import fastapi, uvicorn, nmap" >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] Verification failed. Packages did not install correctly.
    pause
    exit /b 1
)

:launch
:: ===================================================
:: 5. LAUNCH BACKEND
:: ===================================================
echo [*] [5/5] Launching GOT JOED NIDS...
echo ===================================================
echo   SUCCESS - Engine Starting
echo   Keep this window OPEN
echo ===================================================

:: Navigate into backend folder to run main.py natively
cd /d "%BACKEND_DIR%"
"%VENV_PYTHON%" main.py

echo [INFO] Server stopped
pause