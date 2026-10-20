@echo off
setlocal

set CONFIG=Debug
if not "%1"=="" set CONFIG=%1

if "%WindowsSdkVerBinPath%"=="" (
    echo Run from a Visual Studio Developer Command Prompt.
    exit /b 1
)

set ROOT=%~dp0..
set STAGE=%ROOT%\build\catalog
set SYS=%ROOT%\build\AgentLensKernel\x64\%CONFIG%\AgentLensKernel.sys

if not exist "%SYS%" (
    echo Driver not found: %SYS%
    exit /b 1
)

if not exist "%STAGE%" mkdir "%STAGE%"
copy /y "%SYS%" "%STAGE%\AgentLensKernel.sys" >nul
copy /y "%ROOT%\config\AgentLensKernel.inf" "%STAGE%\AgentLensKernel.inf" >nul

cd /d "%STAGE%"

inf2cat.exe /driver:. /os:10_X64
if errorlevel 1 (
    echo inf2cat failed.
    exit /b 1
)

copy /y AgentLensKernel.cat "%ROOT%\config\AgentLensKernel.cat" >nul
echo Catalog generated: AgentLensKernel.cat
exit /b 0
