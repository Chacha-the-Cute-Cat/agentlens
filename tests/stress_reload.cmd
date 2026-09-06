@echo off
setlocal
for /L %%i in (1,1,100) do (
    echo === reload %%i ===
    sc.exe stop AgentLensKernel >nul
    timeout /t 1 /nobreak >nul
    sc.exe start AgentLensKernel >nul
    timeout /t 1 /nobreak >nul
    AgentLensTools.exe --selftest
    if errorlevel 1 exit /b 1
)
echo stress_reload passed
exit /b 0
