@echo off
chcp 65001 >nul
title stock_main v4.0 - 路由主服务 :9000
cd /d %~dp0..

set VENV_PYTHON=%~dp0..\stock_app\venv\Scripts\python.exe

echo.
echo ╔══════════════════════════════════════════════╗
echo ║       stock_main v4.0 路由主服务              ║
echo ║         端口: 9000                           ║
echo ╚══════════════════════════════════════════════╝
echo.

if exist "%VENV_PYTHON%" (
    "%VENV_PYTHON%" stock_main\main_v4.py
) else (
    echo 未找到虚拟环境，尝试系统Python...
    python stock_main\main_v4.py
)

pause