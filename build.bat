@echo off
REM GhostSecure 2.0 ??? Build Script ??? Coded by Egyan
echo.
echo ================================================================
echo   GhostSecure 2.0 - Build .exe
echo ================================================================
echo.

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found. Install Python 3.8+
    pause & exit /b 1
)

echo [1] Installing deps ...
pip install pywin32 ldap3 pyinstaller >nul 2>&1
python -m pywin32_postinstall -install >nul 2>&1

echo [2] Self-test ...
python main.py --test
echo.

echo [3] Building with PyInstaller ...
pyinstaller --onefile --name GhostSecure2 ^
    --hidden-import win32timezone ^
    --hidden-import win32serviceutil ^
    --hidden-import win32service ^
    --hidden-import win32event ^
    --hidden-import servicemanager ^
    --hidden-import win32evtlog ^
    --hidden-import win32con ^
    --hidden-import ldap3 ^
    --hidden-import config ^
    --hidden-import core.alert_manager ^
    --hidden-import core.event_reader ^
    --hidden-import core.detector_engine ^
    --hidden-import detectors.kerberoasting ^
    --hidden-import detectors.pass_the_hash ^
    --hidden-import detectors.dcsync ^
    --hidden-import detectors.golden_ticket ^
    --hidden-import detectors.ldap_recon ^
    --hidden-import detectors.asrep_roasting ^
    --hidden-import detectors.skeleton_key ^
    --hidden-import utils.ad_helpers ^
    --hidden-import utils.time_helpers ^
    --hidden-import gui.status_dashboard ^
    --add-data "config.py;." ^
    --add-data "core;core" ^
    --add-data "detectors;detectors" ^
    --add-data "utils;utils" ^
    --add-data "gui;gui" ^
    --console main.py

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed.
    pause & exit /b 1
)

echo.
echo ================================================================
echo   Built: dist\GhostSecure2.exe
echo   Run Install.bat to deploy as service.
echo ================================================================
pause
