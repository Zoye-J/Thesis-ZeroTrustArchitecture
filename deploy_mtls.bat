@echo off
echo ==============================================
echo ZTA Government System - mTLS Deployment (Windows)
echo ==============================================
echo.

REM Step 1: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

REM Step 2: Check for OpenSSL
where openssl >nul 2>&1
if errorlevel 1 (
    echo WARNING: OpenSSL not found in PATH
    echo.
    echo Installing OpenSSL via Chocolatey...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    choco install openssl -y
    echo Please restart Command Prompt and run this script again
    pause
    exit /b 1
)

REM Step 3: Generate certificates
echo Step 1: Generating certificates...
python create_certificates.py
if %errorlevel% neq 0 (
    echo ERROR: Certificate generation failed
    pause
    exit /b 1
)

REM Step 4: Setup database
echo.
echo Step 2: Setting up database...
python setup_database.py
if %errorlevel% neq 0 (
    echo ERROR: Database setup failed
    pause
    exit /b 1
)

REM Step 5: Start OPA server if exists
echo.
echo Step 3: Starting OPA policy server...
if exist run_opa_server.py (
    echo Starting OPA policy server on port 8181 (HTTPS)...
    start cmd /k "python run_opa_server.py"
    timeout /t 3 /nobreak >nul
)

REM Step 6: Start OPA Agent
echo.
echo Step 4: Starting OPA Agent on port 8282 (HTTPS)...
if exist opa_agent_server.py (
    echo Starting OPA Agent server...
    start cmd /k "python opa_agent_server.py"
    timeout /t 3 /nobreak >nul
)

REM Step 7: Start API Server
echo.
echo Step 5: Starting API Server on port 5001 (HTTPS)...
if exist api_server.py (
    echo Starting API Server...
    start cmd /k "python api_server.py"
    timeout /t 3 /nobreak >nul
)

REM Step 8: Start Gateway Server
echo.
echo Step 6: Starting Gateway Server on port 5000 (HTTPS)...
if exist gateway_server.py (
    echo Starting Gateway Server...
    start cmd /k "python gateway_server.py"
    timeout /t 3 /nobreak >nul
)

REM Step 9: Start Dashboard Server
echo.
echo Step 7: Starting Dashboard Server on port 5002 (HTTPS)...
if exist dashboard_server.py (
    echo Starting Dashboard Server...
    start cmd /k "python dashboard_server.py"
    timeout /t 3 /nobreak >nul
)

echo.
echo ==============================================
echo ✅ ALL SERVERS STARTED SUCCESSFULLY!
echo ==============================================
echo.
echo Application URLs:
echo   Gateway: https://localhost:5000
echo   API Server: https://localhost:5001
echo   OPA Server: https://localhost:8181
echo   OPA Agent: https://localhost:8282
echo   Dashboard: https://localhost:5002
echo.
echo Dashboard Access:
echo   1. Open: https://localhost:5002
echo   2. Login credentials from sample_data.py
echo   3. Monitor real-time events and request flow
echo.
echo To test mTLS with curl:
echo   curl --cert ./certs/clients/1/client.crt ^
echo        --key ./certs/clients/1/client.key ^
echo        --cacert ./certs/ca.crt ^
echo        https://localhost:5000/api/zta-test
echo.
echo Press Ctrl+C in any window to stop that server
echo ==============================================
echo.
pause