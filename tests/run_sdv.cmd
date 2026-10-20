@echo off
setlocal

if "%WindowsSdkVerBinPath%"=="" (
    echo Run from a WDK-enabled Visual Studio Developer Command Prompt.
    exit /b 1
)

msbuild "%~dp0..\src\AgentLensKernel\AgentLensKernel.vcxproj" /t:sdv /p:Configuration=Release /p:Platform=x64 /m
exit /b %ERRORLEVEL%
