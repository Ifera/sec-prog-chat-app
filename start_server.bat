@echo off
setlocal enabledelayedexpansion

rem Usage:
rem   start_server.bat [PORT] [HOST] [INTRODUCERS_JSON]
rem Defaults:
rem   PORT=8080  HOST=0.0.0.0  INTRODUCERS_JSON=introducers.json

set PORT=%1
if "%PORT%"=="" set PORT=8080

set HOST=%2
if "%HOST%"=="" set HOST=0.0.0.0

set INTRO=%3
if "%INTRO%"=="" set INTRO=introducers.json

echo Starting SOCP Server @ %HOST%:%PORT%  (bootstrap via %INTRO%)
set SOCP_IS_INTRODUCER=false
set SOCP_HOST=%HOST%
set SOCP_PORT=%PORT%
set SOCP_INTRODUCERS_JSON=%INTRO%

python server.py
pause
