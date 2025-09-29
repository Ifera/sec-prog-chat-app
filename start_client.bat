@echo off
if "%1"=="" (
    echo Starting SOCP Client with random user ID...
    python client.py
) else (
    echo Starting SOCP Client as user: %1
    python client.py %1
)
pause
