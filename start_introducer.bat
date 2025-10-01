@echo off
setlocal enabledelayedexpansion

rem Usage:
rem   start_introducer.bat [PORT] [INTRODUCERS_JSON]
rem Defaults:
rem   PORT=8000  INTRODUCERS_JSON=introducers.json

set PORT=%1
if "%PORT%"=="" set PORT=8000

set INTRO=%2
if "%INTRO%"=="" set INTRO=introducers.json

echo Starting SOCP Introducer on port %PORT% using %INTRO%
set SOCP_IS_INTRODUCER=true
set SOCP_HOST=0.0.0.0
set SOCP_PORT=%PORT%
set SOCP_INTRODUCERS_JSON=%INTRO%

python server.py
pause
