@echo off
setlocal

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

copy /y "%ROOT%\build\AgentLensService\x64\%CONFIG%\AgentLensService.exe" %SystemRoot%\System32\AgentLensService.exe >nul
sc.exe create AgentLensService type= own start= auto binPath= %SystemRoot%\System32\AgentLensService.exe

if exist "%ROOT%\etw\AgentLensProvider.man" (
    wevtutil.exe im "%ROOT%\etw\AgentLensProvider.man"
)

echo Install completed. You may need to start AgentLensService manually or reboot.
exit /b 0
