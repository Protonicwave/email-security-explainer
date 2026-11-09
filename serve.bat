@echo off
rem Starts the audit page and opens it in the default browser, installing uv
rem first if it is missing. uv then fetches Python 3.12 and the dependencies
rem on the first run. Arguments go to esx serve, for example: serve.bat --port 8080
setlocal
cd /d "%~dp0"

where uv >nul 2>nul
if errorlevel 1 (
    if not defined UV_INSTALL_DIR set "UV_INSTALL_DIR=%USERPROFILE%\.local\bin"
    call :find_or_install_uv
    if errorlevel 1 (
        echo Could not install uv. Install it from https://docs.astral.sh/uv/ and run this again.
        pause
        exit /b 1
    )
)

if not defined ANTHROPIC_API_KEY (
    echo ANTHROPIC_API_KEY is not set: the page can audit domains but not explain them.
)

echo Preparing Python and the dependencies. The first run downloads them.
uv run --locked --no-dev esx serve --open %*
if errorlevel 1 (
    pause
    exit /b 1
)
exit /b 0

:find_or_install_uv
if not exist "%UV_INSTALL_DIR%\uv.exe" (
    echo uv is not installed. Installing uv 0.12.1.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://astral.sh/uv/0.12.1/install.ps1 | iex"
    if errorlevel 1 exit /b 1
)
if not exist "%UV_INSTALL_DIR%\uv.exe" exit /b 1
set "PATH=%UV_INSTALL_DIR%;%PATH%"
exit /b 0
