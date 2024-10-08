
@echo off
:: https://posts.specterops.io/relay-your-heart-away-an-opsec-conscious-approach-to-445-takeover-1c9b4666c8ac
if "%1"=="" (
    echo Usage: smb_control.bat [start^|stop^|status]
    exit /b 1
)

REM Validate that the argument is either "start" or "stop"
if /i "%1"=="start" (
    echo Setting LanmanServer to auto-start...
    sc config LanmanServer start= auto

    echo Starting services...
    sc start srvnet
    sc start srv2
    sc start LanmanServer
    echo Services started.
) else if /i "%1"=="stop" (
    echo Stopping services...
    sc stop LanmanServer
    sc stop srv2
    sc stop srvnet
    echo Services stopped.
) else if /i "%1"=="status" (
    
    sc queryex LanmanServer | find "RUNNING" >nul
	if %errorlevel%==0 (
    echo LanmanServer is running.
	) else (
    echo LanmanServer is not running.
	)
	    sc queryex srv2 | find "RUNNING" >nul
	if %errorlevel%==0 (
    echo srv2 is running.
	) else (
    echo srv2 is not running.
	)
    sc queryex srvnet | find "RUNNING" >nul
	if %errorlevel%==0 (
    echo srvnet is running.
	) else (
    echo srvnet is not running.
	)


    
) else (
    echo Invalid argument: "%1"
    echo Usage: smb_control.bat [start^|stop^|staus]
    exit /b 1
)
