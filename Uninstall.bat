@echo off
REM GhostSecure 2.1 - Uninstall Script - Coded by Egyan
echo.
echo ================================================================
echo   GhostSecure 2.1 - Uninstallation
echo   Coded by Egyan
echo ================================================================
echo.

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Run as Administrator.
    pause & exit /b 1
)

echo [1] Stopping service ...
net stop GhostSecure2ADDetector >nul 2>&1
timeout /t 3 /nobreak >nul

echo [2] Removing service ...
set "EXE=%~dp0dist\GhostSecure2.exe"
if not exist "%EXE%" set "EXE=%~dp0GhostSecure2.exe"
if exist "%EXE%" (
    "%EXE%" remove
) else (
    sc delete GhostSecure2ADDetector >nul 2>&1
    python "%~dp0main.py" remove >nul 2>&1
)
echo [OK]
echo.

set /p DEL_LOGS="Delete logs in C:\SecurityLogs? (y/N): "
if /i "%DEL_LOGS%"=="y" (
    del /q "C:\SecurityLogs\ad_attack_log.txt" >nul 2>&1
    del /q "C:\SecurityLogs\ghostsecure_service.log*" >nul 2>&1
    del /q "C:\SecurityLogs\ghostsecure_state.json" >nul 2>&1
    echo [OK] Logs deleted.
) else (
    echo [OK] Logs kept.
)

echo.
echo ================================================================
echo   Uninstall complete. Run Install.bat to reinstall.
echo ================================================================
pause
