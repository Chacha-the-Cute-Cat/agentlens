@echo off
setlocal
AgentLensTools.exe --fuzz-ioctl 10000
exit /b %ERRORLEVEL%
