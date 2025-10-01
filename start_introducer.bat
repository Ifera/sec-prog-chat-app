@echo off
setlocal enabledelayedexpansion

rem --------------------------------------------
rem Usage:
rem   start_introducer.bat [PORT] [INTRODUCERS_JSON]
rem Precedence:
rem   1) CLI args override
rem   2) .introducer.env (if present) else .server.env
rem   3) Defaults
rem Defaults:
rem   PORT=8000  HOST=127.0.0.1  INTRODUCERS_JSON=introducers.json  IS_INTRODUCER=true
rem --------------------------------------------

set "ENV_FILE=.introducer.env"

rem 1) Load from env file if present (key=value; supports #/; comments and quoted values)
if exist "%ENV_FILE%" (
  for /f "usebackq tokens=1* delims== eol=#" %%A in ("%ENV_FILE%") do (
    set "NAME=%%~A"
    set "VALUE=%%~B"
    if not "!NAME:~0,1!"==";" (
      if defined VALUE (
        if "!VALUE:~0,1!"=="\"" if "!VALUE:~-1!"=="\"" set "VALUE=!VALUE:~1,-1!"
      )
      set "!NAME!=!VALUE!"
    )
  )
)

rem 2) Apply defaults if not defined by env file
if not defined PORT set "PORT=8000"
if not defined HOST set "HOST=127.0.0.1"
if not defined INTRODUCERS_JSON set "INTRODUCERS_JSON=introducers.json"
if not defined IS_INTRODUCER set "IS_INTRODUCER=true"

rem 3) CLI args override env/defaults
if not "%~1"=="" set "PORT=%~1"
if not "%~2"=="" set "INTRODUCERS_JSON=%~2"

echo.
echo Starting Introducer with:
echo   HOST              = %HOST%
echo   PORT              = %PORT%
echo   INTRODUCERS_JSON  = %INTRODUCERS_JSON%
echo   IS_INTRODUCER     = %IS_INTRODUCER%
echo.

rem Export variables for the Python process
set "HOST=%HOST%"
set "PORT=%PORT%"
set "INTRODUCERS_JSON=%INTRODUCERS_JSON%"
set "IS_INTRODUCER=%IS_INTRODUCER%"

python server.py
echo.
pause
