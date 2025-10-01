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

echo Starting Introducer on port %PORT% using %INTRO%
set IS_INTRODUCER=true
set HOST=0.0.0.0
set PORT=%PORT%
set INTRODUCERS_JSON=%INTRO%

python server.py
pause
