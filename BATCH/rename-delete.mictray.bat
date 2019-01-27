echo off 
SETLOCAL EnableDelayedExpansion
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set "DEL=%%a"
)
::check_Permissions
    echo Administrative permissions required. Detecting permissions...

    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo Success: Administrative permissions confirmed.
    ) else (
        echo Failure: Current permissions inadequate.
		pause
		exit
    )
    pause

echo Moving to root of C...
cd C:\
echo Force stop of task and kill MicTray process...
TASKKILL /IM MicTray.exe /F
echo Force stop of task and kill Mictray64 process...
TASKKILL /IM MicTray64.exe /F
echo Locate and rename MicTray binaries
for /f "delims=" %%i in ('dir /s /b /a-d "MicTray.exe"') do (ren "%%i" MicTray.old)
echo Locate and rename MicTray64 binaries
for /f "delims=" %%i in ('dir /s /b /a-d "MicTray64.exe"') do (ren "%%i" MicTray.old)
echo Locate and rename MicTray.log
for /f "delims=" %%i in ('dir /s /b /a-d "MicTray.log"') do (ren "%%i" MicTray.old)
call :ColorText 47 "You may need to reboot this machine depending on the above line." 
echo.
echo Now to delete all old files
for /f "delims=" %%i in ('dir /s /b /a-d "MicTray.old"') do (del "%%i" MicTray.old)
echo Letting you double check the events. When you are ready...
pause
goto :eof

:ColorText
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1
goto :eof
