@echo off
REM ============================================
REM  ???????? - zdjy.github.io
REM  ??: ???? ? update "??????"
REM ============================================
cd /d C:\Users\wf\Documents\GitHub\zdjy.github.io

echo.
echo === ?????? ===
"C:\Program Files\Git\cmd\git.exe" status --short

if %errorlevel% neq 0 (
    echo ???????? Git ???
    pause
    exit /b 1
)

"C:\Program Files\Git\cmd\git.exe" diff --stat

echo.
echo === ?????? ===
"C:\Program Files\Git\cmd\git.exe" add --all

echo.
echo === ???? ===
if "%~1"=="" (
    set MSG=Update website
) else (
    set MSG=%~1
)
"C:\Program Files\Git\cmd\git.exe" commit -m "%MSG%"

echo.
echo === ??? GitHub ===
"C:\Program Files\Git\cmd\git.exe" push origin main

echo.
echo ============================================
echo  ????????
echo  https://jiaokai-jj.github.io/zdjy.github.io
echo ============================================
pause
