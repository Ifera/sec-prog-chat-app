@echo off
setlocal enabledelayedexpansion

rem Usage:
rem   start_client.bat [USER_ID] [SERVER_HOST] [SERVER_PORT]
rem Defaults:
rem   USER_ID=random  HOST=127.0.0.1  PORT=8080

set USER=%1
set SERVER_HOST=%2
set SERVER_PORT=%3

if "%SERVER_HOST%"=="" set SERVER_HOST=127.0.0.1
if "%SERVER_PORT%"=="" set SERVER_PORT=8080

echo Connecting client to wss://%SERVER_HOST%:%SERVER_PORT%/ws
if "%USER%"=="" (
    python client.py
) else (
    python client.py %USER%
)
pause
