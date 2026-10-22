@echo off
setlocal

net session >nul 2>&1
if errorlevel 1 (
    echo Run this script from an elevated command prompt.
    exit /b 1
)

set CONFIG=Debug
if not "%1"=="" set CONFIG=%1

set ROOT=%~dp0..
set SYS=%ROOT%\build\AgentLensKernel\x64\%CONFIG%\AgentLensKernel.sys
set STAGE=%ROOT%\build\install

if not exist "%SYS%" (
    echo Driver not found: %SYS%
    exit /b 1
)

if not exist "%STAGE%" mkdir "%STAGE%"
copy /y "%SYS%" "%STAGE%\AgentLensKernel.sys" >nul
copy /y "%ROOT%\config\AgentLensKernel.inf" "%STAGE%\AgentLensKernel.inf" >nul
if exist "%ROOT%\config\AgentLensKernel.cat" (
    copy /y "%ROOT%\config\AgentLensKernel.cat" "%STAGE%\AgentLensKernel.cat" >nul
)

InfDefaultInstall.exe "%STAGE%\AgentLensKernel.inf"
if errorlevel 1 (
    echo INF installation failed. Generate and sign the catalog first, or use a test-signed VM.
    exit /b 1
)
sc.exe start AgentLensKernel

sc.exe query AgentLensService >nul 2>&1
if not errorlevel 1 (
    echo Stopping the existing AgentLensService.
    sc.exe stop AgentLensService >nul 2>&1
    timeout /t 2 /nobreak >nul
)

copy /y "%ROOT%\build\AgentLensService\x64\%CONFIG%\AgentLensService.exe" %SystemRoot%\System32\AgentLensService.exe >nul
if errorlevel 1 (
    echo Failed to copy AgentLensService.exe.
    exit /b 1
)

sc.exe query AgentLensService >nul 2>&1
if errorlevel 1 (
    sc.exe create AgentLensService type= own start= delayed-auto binPath= "%SystemRoot%\System32\AgentLensService.exe"
) else (
    sc.exe config AgentLensService binPath= "%SystemRoot%\System32\AgentLensService.exe"
    sc.exe config AgentLensService start= delayed-auto
)
if errorlevel 1 (
    echo Failed to configure AgentLensService.
    exit /b 1
)

sc.exe config AgentLensService depend= AgentLensKernel
if errorlevel 1 (
    echo Failed to set the AgentLensKernel dependency.
    exit /b 1
)

if exist "%ROOT%\etw\AgentLensProvider.man" (
    wevtutil.exe im "%ROOT%\etw\AgentLensProvider.man"
)

sc.exe start AgentLensService
if errorlevel 1 (
    echo Failed to start AgentLensService.
    exit /b 1
)

echo Install completed.
echo Event log: %%ProgramData%%\AgentLens\events.jsonl
echo Service log: %%ProgramData%%\AgentLens\service.log
exit /b 0
