@echo off
title GraphShield
cd /d "%~dp0.."
echo =====================================================
echo  GraphShield Hybrid Identity Security Platform
echo =====================================================
echo.
echo [*] Starting application - please wait...
echo [*] Once ready, your browser will open automatically.
echo.
start /b "" python -m streamlit run app.py --server.port=8501 --server.address=127.0.0.1 --server.headless true
echo.
echo [*] Waiting for app to start...
timeout /t 10 /nobreak >nul
echo [*] Opening browser...
start http://localhost:8501
echo.
echo =====================================================
echo  App running at: http://localhost:8501
echo  Close this window to stop the application.
echo =====================================================
