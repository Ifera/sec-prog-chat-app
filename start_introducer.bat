@echo off
echo Starting SOCP Introducer Server...
set SOCP_IS_INTRODUCER=true
set SOCP_PORT=8081
python server.py
pause
