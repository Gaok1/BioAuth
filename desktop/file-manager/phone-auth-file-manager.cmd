@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0phone-auth-file-manager.ps1" -Action auto %*
exit /b %ERRORLEVEL%
