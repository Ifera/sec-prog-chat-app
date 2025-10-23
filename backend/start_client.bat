@echo off
setlocal enabledelayedexpansion

rem Usage:
rem   start_client.bat <PASSWORD> [USER_ID] [SERVER_HOST] [SERVER_PORT]
rem Defaults:
rem   USER_ID=random  HOST=127.0.0.1  PORT=8080

set PASSWORD=%1
set USER=%2
set SERVER_HOST=%3
set SERVER_PORT=%4

if "%PASSWORD%"=="" (
    echo Error: PASSWORD argument is required.
    echo Usage: start_client.bat ^<PASSWORD^> [USER_ID] [SERVER_HOST] [SERVER_PORT]
    echo Example: start_client.bat mysecretpassword
    echo.
    exit /b 1
)

if "%SERVER_HOST%"=="" set SERVER_HOST=127.0.0.1
if "%SERVER_PORT%"=="" set SERVER_PORT=8080

echo Connecting client to wss://%SERVER_HOST%:%SERVER_PORT%/ws
if "%USER%"=="" (
    python client.py %PASSWORD%
) else (
    python client.py %PASSWORD% %USER%
)
pause
