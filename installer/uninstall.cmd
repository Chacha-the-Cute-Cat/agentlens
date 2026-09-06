@echo off
setlocal

sc.exe stop AgentLensService
sc.exe delete AgentLensService
sc.exe stop AgentLensKernel
sc.exe delete AgentLensKernel

wevtutil.exe um ..\etw\AgentLensProvider.man

del /f /q %SystemRoot%\System32\drivers\AgentLensKernel.sys
del /f /q %SystemRoot%\System32\AgentLensService.exe

echo Uninstall completed.
exit /b 0
