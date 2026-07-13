@echo off
setlocal
"%~dp0.venv\Scripts\python.exe" "%~dp0wechat_manager.py" %*
exit /b %ERRORLEVEL%
