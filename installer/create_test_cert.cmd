@echo off
setlocal

if exist AgentLensTestCert.cer goto have_cert

makecert.exe -r -pe -ss PrivateCertStore -n "CN=AgentLens Test" AgentLensTestCert.cer
if errorlevel 1 (
    echo makecert failed. Ensure Windows SDK tools are in PATH.
    exit /b 1
)

:have_cert
certutil.exe -addstore Root AgentLensTestCert.cer
certutil.exe -addstore TrustedPublisher AgentLensTestCert.cer
echo Test certificate installed.
exit /b 0
