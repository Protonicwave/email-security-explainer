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
rem The release archive is checked against the hash GitHub published for it,
rem so nothing downloaded runs unless it is the file pinned here.
set "UV_ZIP_URL=https://github.com/astral-sh/uv/releases/download/0.12.1/uv-x86_64-pc-windows-msvc.zip"
set "UV_ZIP_SHA256=8fcb0cb46e1229065e344758980924e569bef5882ef45f46fada8fb24e06b74a"
if not exist "%UV_INSTALL_DIR%\uv.exe" (
    echo uv is not installed. Downloading uv 0.12.1 and checking its SHA-256.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $zip = Join-Path $env:TEMP 'uv-0.12.1.zip'; Invoke-WebRequest -UseBasicParsing -Uri $env:UV_ZIP_URL -OutFile $zip; if ((Get-FileHash -Algorithm SHA256 $zip).Hash -ne $env:UV_ZIP_SHA256) { Remove-Item $zip; throw 'the download does not match the pinned SHA-256' }; Expand-Archive -Force $zip $env:UV_INSTALL_DIR; Remove-Item $zip"
    if errorlevel 1 exit /b 1
)
if not exist "%UV_INSTALL_DIR%\uv.exe" exit /b 1
set "PATH=%UV_INSTALL_DIR%;%PATH%"
exit /b 0
