@echo off
setlocal
echo Enabling Driver Verifier for AgentLensKernel.sys...
verifier.exe /standard /driver AgentLensKernel.sys
verifier.exe /querysettings
echo Reboot is required for Driver Verifier to take effect.
exit /b 0
