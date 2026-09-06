@echo off
setlocal
echo Disabling Driver Verifier...
verifier.exe /reset
echo Reboot is required to fully disable Driver Verifier.
exit /b 0
