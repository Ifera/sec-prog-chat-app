@echo off
setlocal enabledelayedexpansion

rem --------------------------------------------
rem Usage:
rem   start_server.bat [PORT] [HOST] [INTRODUCERS_JSON]
rem Sources:
rem   1) CLI args override
rem   2) .server.env (if present) key=value
rem   3) Defaults
rem --------------------------------------------

set "ENV_FILE=.server.env"

rem 1) Load from .server.env if present
if exist "%ENV_FILE%" (
  for /f "usebackq tokens=1* delims== eol=#" %%A in ("%ENV_FILE%") do (
    set "NAME=%%~A"
    set "VALUE=%%~B"
    rem skip lines that start with ';'
    if not "!NAME:~0,1!"==";" (
      rem trim surrounding quotes from VALUE if present
      if defined VALUE (
        if "!VALUE:~0,1!"=="\"" if "!VALUE:~-1!"=="\"" set "VALUE=!VALUE:~1,-1!"
      )
      set "!NAME!=!VALUE!"
    )
  )
)

rem 2) Apply defaults if not defined by env file
if not defined PORT set "PORT=8080"
if not defined HOST set "HOST=127.0.0.1"
if not defined INTRODUCERS_JSON set "INTRODUCERS_JSON=introducers.json"

rem 3) CLI args override env/defaults
if not "%~1"=="" set "PORT=%~1"
if not "%~2"=="" set "HOST=%~2"
if not "%~3"=="" set "INTRODUCERS_JSON=%~3"

echo.
echo Starting Server with:
echo   HOST              = %HOST%
echo   PORT              = %PORT%
echo   INTRODUCERS_JSON  = %INTRODUCERS_JSON%
echo.

rem Export variables for the Python process
set "HOST=%HOST%"
set "PORT=%PORT%"
set "INTRODUCERS_JSON=%INTRODUCERS_JSON%"

python server.py
echo.
pause
