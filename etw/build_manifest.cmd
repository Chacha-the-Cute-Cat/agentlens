@echo off
setlocal

if "%WindowsSdkVerBinPath%"=="" (
    echo Run from a Visual Studio Developer Command Prompt.
    exit /b 1
)

mc.exe -um AgentLensProvider.man -z AgentLensProvider
rc.exe AgentLensProvider.rc
echo Manifest built.
exit /b 0
