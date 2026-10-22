@echo off
setlocal

net session >nul 2>&1
if errorlevel 1 (
    echo Run this script from an elevated command prompt.
    exit /b 1
)

for %%I in ("%~dp0..") do set ROOT=%%~fI

sc.exe stop AgentLensService
timeout /t 2 /nobreak >nul
sc.exe delete AgentLensService
sc.exe stop AgentLensKernel
timeout /t 2 /nobreak >nul
sc.exe delete AgentLensKernel

if exist "%ROOT%\etw\AgentLensProvider.man" (
    wevtutil.exe um "%ROOT%\etw\AgentLensProvider.man"
)

del /f /q %SystemRoot%\System32\drivers\AgentLensKernel.sys
del /f /q %SystemRoot%\System32\AgentLensService.exe

echo Uninstall completed.
exit /b 0
