@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "PROJECT_DIR=%SCRIPT_DIR%"
if not exist "%PROJECT_DIR%\package.json" set "PROJECT_DIR=D:\GIT\VKarmani"

if not exist "%PROJECT_DIR%\package.json" (
    echo [ERROR] package.json not found.
    echo Put this BAT file in the project root or fix PROJECT_DIR inside the script.
    echo.
    pause
    exit /b 1
)

cd /d "%PROJECT_DIR%"

set "APP_VERSION=unknown"
for /f "usebackq delims=" %%V in (`node -p "require('./package.json').version" 2^>nul`) do set "APP_VERSION=%%V"
if "%APP_VERSION%"=="" set "APP_VERSION=unknown"

title VKarmani Desktop v%APP_VERSION% Dev

echo =========================================
echo      VKarmani Desktop v%APP_VERSION% Dev Start
echo =========================================
echo.

where node >nul 2>nul || (
  echo [ERROR] Node.js not found in PATH.
  echo Install Node.js LTS and reopen the terminal.
  echo.
  pause
  exit /b 1
)

where npm >nul 2>nul || (
  echo [ERROR] npm not found in PATH.
  echo Install Node.js LTS and reopen the terminal.
  echo.
  pause
  exit /b 1
)

set "XRAY_PATH=%PROJECT_DIR%\resources\core\windows\xray.exe"
if not exist "%XRAY_PATH%" (
    echo [ERROR] xray.exe not found:
    echo %XRAY_PATH%
    echo.
    pause
    exit /b 1
)
set "VKARMANI_XRAY_PATH=%XRAY_PATH%"

if not exist "%PROJECT_DIR%\resources\core\windows\geoip.dat" (
    echo [WARN] geoip.dat not found: %PROJECT_DIR%\resources\core\windows\geoip.dat
)
if not exist "%PROJECT_DIR%\resources\core\windows\geosite.dat" (
    echo [WARN] geosite.dat not found: %PROJECT_DIR%\resources\core\windows\geosite.dat
)
if not exist "%PROJECT_DIR%\resources\core\windows\wintun.dll" (
    echo [WARN] wintun.dll not found: %PROJECT_DIR%\resources\core\windows\wintun.dll
    echo [WARN] TUN mode will fail until you place the official amd64 wintun.dll next to xray.exe.
)

if not exist ".env" if exist ".env.example" (
    echo [INFO] Creating .env from .env.example
    copy /Y ".env.example" ".env" >nul
)

set "REPAIRED=0"
if not exist "node_modules" (
    echo [INFO] Installing npm dependencies...
    call npm install --include=dev --registry=https://registry.npmjs.org/
    if errorlevel 1 goto :npm_failed
    set "REPAIRED=1"
)

call :ensure_pkg "@vitejs/plugin-react/package.json" "npm install -D @vitejs/plugin-react@4.3.1" "@vitejs/plugin-react"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "vite/package.json" "npm install -D vite@5.4.10" "vite"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "typescript/package.json" "npm install -D typescript@5.6.3" "typescript"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "lucide-react/package.json" "npm install lucide-react@0.511.0" "lucide-react"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "react/jsx-runtime" "npm install react@18.3.1 react-dom@18.3.1" "react/react-dom"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "caniuse-lite/dist/unpacker/agents" "npm install caniuse-lite browserslist" "caniuse-lite/browserslist"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "@tauri-apps/cli/package.json" "npm install -D @tauri-apps/cli@2.10.1" "@tauri-apps/cli"
if errorlevel 1 goto :npm_failed

if "%REPAIRED%"=="1" (
    if exist "node_modules\.vite" rmdir /s /q "node_modules\.vite"
)

echo [INFO] PROJECT_DIR=%PROJECT_DIR%
echo [INFO] VKARMANI_XRAY_PATH=%VKARMANI_XRAY_PATH%
echo [INFO] Starting VKarmani v%APP_VERSION%...
echo.

call npx tauri dev
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if "%EXIT_CODE%"=="0" (
    echo [INFO] Process finished.
) else (
    echo [ERROR] tauri dev exited with code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%

:ensure_pkg
node -e "require.resolve('%~1')" >nul 2>nul
if errorlevel 1 (
    echo [INFO] Missing or broken %~3. Repairing...
    call %~2 --registry=https://registry.npmjs.org/
    if errorlevel 1 exit /b 1
    set "REPAIRED=1"
)
exit /b 0

:npm_failed
echo.
echo [ERROR] npm install failed.
echo.
pause
exit /b 1
