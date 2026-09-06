@echo off
setlocal
AgentLensTools.exe --selftest
exit /b %ERRORLEVEL%
