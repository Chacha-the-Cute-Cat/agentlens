@echo off
setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Debug

msbuild AgentLens.sln /t:Build /p:Configuration=%CONFIG% /p:Platform=x64 /m
exit /b %ERRORLEVEL%
