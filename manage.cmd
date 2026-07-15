@echo off
setlocal
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Repository environment is missing. Run .\setup.ps1 first. 1>&2
  exit /b 2
)
"%~dp0.venv\Scripts\python.exe" "%~dp0wechat_manager.py" %*
exit /b %ERRORLEVEL%
