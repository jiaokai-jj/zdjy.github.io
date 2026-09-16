@echo off
setlocal
set "PATH=C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;%PATH%"
cd /d "%~dp0"
set "PYTHONIOENCODING=gbk"

set "PY=C:\Users\jk\AppData\Local\Programs\Python\Python311\python.exe"
if not exist "%PY%" goto trypy2
goto haspy

:trypy2
set "PY=C:\Users\jk\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PY%" goto trypy3
goto haspy

:trypy3
where python >nul 2>nul
if errorlevel 1 goto nopy
set "PY=python"
goto haspy

:nopy
echo.
echo   没有找到 Python，无法继续。
echo   请确认本机安装了 Python 3。
echo.
pause
exit /b 1

:haspy
echo.
echo   Python: %PY%
echo.
"%PY%" "%~dp0publish_release.py" %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" goto done
echo   执行未成功，返回码 %RC%，请查看上方错误信息。
echo.
pause
exit /b %RC%

:done
echo   全部完成。
echo.
pause
exit /b 0

