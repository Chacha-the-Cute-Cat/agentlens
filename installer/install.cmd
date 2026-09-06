@echo off
setlocal

set CONFIG=Debug
if not "%1"=="" set CONFIG=%1

set SYS=..\build\AgentLensKernel\x64\%CONFIG%\AgentLensKernel.sys
if not exist "%SYS%" (
    echo Driver not found: %SYS%
    exit /b 1
)

copy /y "%SYS%" %SystemRoot%\System32\drivers\AgentLensKernel.sys
sc.exe create AgentLensKernel type= kernel start= demand binPath= System32\drivers\AgentLensKernel.sys
sc.exe start AgentLensKernel

copy /y ..\build\AgentLensService\x64\%CONFIG%\AgentLensService.exe %SystemRoot%\System32\AgentLensService.exe
sc.exe create AgentLensService type= own start= auto binPath= %SystemRoot%\System32\AgentLensService.exe

if exist ..\etw\AgentLensProvider.man (
    wevtutil.exe im ..\etw\AgentLensProvider.man
)

echo Install completed. You may need to start AgentLensService manually or reboot.
exit /b 0
