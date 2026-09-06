@echo off
setlocal

set CONFIG=Debug
if not "%1"=="" set CONFIG=%1

set SYS=..\build\AgentLensKernel\x64\%CONFIG%\AgentLensKernel.sys
if not exist "%SYS%" (
    echo Driver not found: %SYS%
    exit /b 1
)

signtool.exe sign /v /s PrivateCertStore /n "AgentLens Test" /fd sha256 /t http://timestamp.digicert.com "%SYS%"
if errorlevel 1 (
    echo signtool failed.
    exit /b 1
)

echo Driver signed: %SYS%
exit /b 0
