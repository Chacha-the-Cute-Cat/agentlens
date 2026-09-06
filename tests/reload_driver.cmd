@echo off
setlocal
echo Stopping AgentLensKernel...
sc.exe stop AgentLensKernel
timeout /t 2 /nobreak >nul
echo Starting AgentLensKernel...
sc.exe start AgentLensKernel
exit /b %ERRORLEVEL%
