@echo off
setlocal
AgentLensTools.exe --fuzz-policy 10000
exit /b %ERRORLEVEL%
