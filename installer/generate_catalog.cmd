@echo off
setlocal

if "%WindowsSdkVerBinPath%"=="" (
    echo Run from a Visual Studio Developer Command Prompt.
    exit /b 1
)

cd /d ..\config

inf2cat.exe /driver:. /os:10_X64
if errorlevel 1 (
    echo inf2cat failed.
    exit /b 1
)

echo Catalog generated: AgentLensKernel.cat
exit /b 0
