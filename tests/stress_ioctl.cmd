@echo off
setlocal
echo Run this in a test VM only.
AgentLensTools.exe --selftest
echo.
echo Additional malformed IOCTL testing should be driven by a dedicated fuzzer.
exit /b 0
