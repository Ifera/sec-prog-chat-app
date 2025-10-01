@echo off
setlocal enabledelayedexpansion

rem Usage:
rem   start_client.bat [USER_ID] [SERVER_HOST] [SERVER_PORT]
rem Defaults:
rem   USER_ID=random  HOST=127.0.0.1  PORT=8080

set USER=%1
set HOST=%2
set PORT=%3

if "%HOST%"=="" set HOST=127.0.0.1
if "%PORT%"=="" set PORT=8080

echo Connecting client to ws://%HOST%:%PORT%/ws
if "%USER%"=="" (
    python client.py
) else (
    python client.py %USER%
)
pause
