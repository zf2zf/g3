@echo off
setlocal
chcp 65001 >nul

REM 双击即用：自动请求管理员权限，再调用同目录的 windows-install-ca.ps1
REM 需把 myCA.crt 与本 .bat 放在同一目录

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 需要管理员权限，正在弹出 UAC 提权...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows-install-ca.ps1"

echo.
pause
