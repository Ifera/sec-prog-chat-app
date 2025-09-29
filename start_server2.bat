@echo off
echo Starting SOCP Server (will bootstrap to introducer)...
set SOCP_PORT=8083
set BOOTSTRAP_HOST_1=localhost
set BOOTSTRAP_PORT_1=8081
python server.py
pause
