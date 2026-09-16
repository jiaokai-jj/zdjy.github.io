@echo off
set "PATH=C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;%PATH%"
cd /d "%~dp0"

echo ============================================================
echo   5.0.1 publish script
echo ------------------------------------------------------------
echo   Pre: build + VMProtect done, output in --1\dist
echo ============================================================
echo.

set "PY=C:\Users\jk\AppData\Local\Programs\Python\Python311\python.exe"
set "GIT=git"
set "GITID=-c user.name=jiaokai-jj -c user.email=jiaokai-jj@users.noreply.github.com"
where git >nul 2>nul
if not errorlevel 1 goto gitok
rem auto-detect newest GitHub Desktop bundled git (do not hardcode app-x.y.z)
for /d %%D in ("%LOCALAPPDATA%\GitHubDesktop\app-*") do (
    if exist "%%D\resources\app\git\cmd\git.exe" set "GIT=%%D\resources\app\git\cmd\git.exe"
)
if not "%GIT%"=="git" goto gitok
for /d %%D in ("%LOCALAPPDATA%\GitHubDesktop\app-*") do (
    if exist "%%D\resources\app\git\mingw64\bin\git.exe" set "GIT=%%D\resources\app\git\mingw64\bin\git.exe"
)
:gitok
echo   git: %GIT%

echo [1/5] check VMP ...
"%PY%" _check_vmp_20260912.py
if errorlevel 1 goto :fail
echo.

echo [2/5] repack zip ...
"%PY%" _pack_downloads_20260911.py --all
if errorlevel 1 goto :fail
echo.

echo [3/5] refresh links and sha256 ...
"%PY%" _refresh_downloads_20260912.py
if errorlevel 1 goto :fail
echo.

echo [4/5] commit ...
"%GIT%" %GITID% add index.html version.txt updates.html worker.js
if errorlevel 1 goto :fail
"%GIT%" %GITID% add -A downloads
if errorlevel 1 goto :fail
"%GIT%" %GITID% commit -m "release v5.0.1: split download + changelog + sha256"
if errorlevel 1 goto :fail
echo.

echo [5/5] push ...
"%GIT%" %GITID% push origin HEAD
if not errorlevel 1 goto pushed
echo   push failed (network?). retry 1 in 8s ...
ping -n 9 127.0.0.1 >nul
"%GIT%" %GITID% push origin HEAD
if not errorlevel 1 goto pushed
echo   retry 2 in 16s ...
ping -n 17 127.0.0.1 >nul
"%GIT%" %GITID% push origin HEAD
if not errorlevel 1 goto pushed
echo   retry 3 in 24s ...
ping -n 25 127.0.0.1 >nul
"%GIT%" %GITID% push origin HEAD
if not errorlevel 1 goto pushed
goto :fail
:pushed
echo.

echo ============================================================
echo   pushed. pages live in 1-3 min: www.jyt.cc.cd
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [stop] one step failed, nothing pushed. check and run again.
echo tip: if push fails on auth, use GitHub Desktop to Push.
pause
exit /b 1
