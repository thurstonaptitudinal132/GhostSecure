@echo off
REM GhostSecure 2.1 - Install Script - Coded by Egyan
echo.
echo ================================================================
echo   GhostSecure 2.1 - AD Attack Detector - Installation
echo   Coded by Egyan - Red Parrot Accounting Ltd
echo ================================================================
echo.

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Run as Administrator.
    pause & exit /b 1
)

echo [1] Creating C:\SecurityLogs\ ...
if not exist "C:\SecurityLogs\" mkdir "C:\SecurityLogs\"
icacls "C:\SecurityLogs" /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F" >nul 2>&1
echo [OK]
echo.

set "EXE=%~dp0dist\GhostSecure2.exe"
if not exist "%EXE%" set "EXE=%~dp0GhostSecure2.exe"

if exist "%EXE%" (
    echo [2] Installing service from %EXE% ...
    "%EXE%" install
    echo [3] Setting auto-start ...
    sc config GhostSecure2ADDetector start= auto >nul 2>&1
    sc failure GhostSecure2ADDetector reset= 86400 actions= restart/60000/restart/120000/restart/300000 >nul 2>&1
    echo [4] Starting service ...
    "%EXE%" start
) else (
    echo [2] .exe not found - installing via Python ...
    pip install pywin32 ldap3 >nul 2>&1
    python -m pywin32_postinstall -install >nul 2>&1
    python "%~dp0main.py" install
    sc config GhostSecure2ADDetector start= auto >nul 2>&1
    python "%~dp0main.py" start
)

echo.
echo ================================================================
echo   Done! Service: GhostSecure2ADDetector
echo   Logs: C:\SecurityLogs\ad_attack_log.txt
echo   Check: sc query GhostSecure2ADDetector
echo ================================================================
pause
