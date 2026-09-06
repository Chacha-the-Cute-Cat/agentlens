@echo off
setlocal

cd /d ..\config

signtool.exe sign /v /s PrivateCertStore /n "AgentLens Test" /fd sha256 /t http://timestamp.digicert.com AgentLensKernel.cat
if errorlevel 1 (
    echo signtool catalog failed.
    exit /b 1
)

echo Catalog signed.
exit /b 0
