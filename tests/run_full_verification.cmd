@echo off
setlocal

echo Step 1: Enable Driver Verifier.
call enable_driver_verifier.cmd
if errorlevel 1 exit /b 1

echo.
echo Please reboot the test VM, then run:
echo   tests\run_post_reboot_tests.cmd
exit /b 0
