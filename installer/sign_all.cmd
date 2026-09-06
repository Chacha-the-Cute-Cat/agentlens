@echo off
setlocal

set CONFIG=Debug
if not "%1"=="" set CONFIG=%1

set ROOT=..\build

signtool.exe sign /v /s PrivateCertStore /n "AgentLens Test" /fd sha256 /t http://timestamp.digicert.com "%ROOT%\AgentLensKernel\x64\%CONFIG%\AgentLensKernel.sys"
if errorlevel 1 goto fail

signtool.exe sign /v /s PrivateCertStore /n "AgentLens Test" /fd sha256 /t http://timestamp.digicert.com "%ROOT%\AgentLensService\x64\%CONFIG%\AgentLensService.exe"
if errorlevel 1 goto fail

signtool.exe sign /v /s PrivateCertStore /n "AgentLens Test" /fd sha256 /t http://timestamp.digicert.com "%ROOT%\AgentLensAgent\x64\%CONFIG%\AgentLensAgent.dll"
if errorlevel 1 goto fail

signtool.exe sign /v /s PrivateCertStore /n "AgentLens Test" /fd sha256 /t http://timestamp.digicert.com "%ROOT%\AgentLensTools\x64\%CONFIG%\AgentLensTools.exe"
if errorlevel 1 goto fail

echo All AgentLens binaries signed.
exit /b 0

:fail
echo signing failed
exit /b 1
