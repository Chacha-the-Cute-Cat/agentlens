@echo off
setlocal

echo [1/5] Self test
AgentLensTools.exe --selftest
if errorlevel 1 exit /b 1

echo [2/5] IOCTL fuzz
AgentLensTools.exe --fuzz-ioctl 10000
if errorlevel 1 exit /b 1

echo [3/5] Reload stress
call stress_reload.cmd
if errorlevel 1 exit /b 1

echo [4/5] Driver Verifier query
verifier.exe /querysettings

echo [5/5] Done
exit /b 0
