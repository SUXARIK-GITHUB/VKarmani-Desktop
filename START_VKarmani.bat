@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "PROJECT_DIR=%SCRIPT_DIR%"
if not exist "%PROJECT_DIR%\package.json" set "PROJECT_DIR=D:\GIT\VKarmani-Desktop"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=run"
if /I "%MODE%"=="start" set "MODE=run"
if /I "%MODE%"=="app" set "MODE=run"

if not exist "%PROJECT_DIR%\package.json" (
    echo [ERROR] package.json not found.
    echo Put START_VKarmani.bat in the VKarmani-Desktop folder or edit PROJECT_DIR in the BAT.
    echo.
    pause
    exit /b 1
)

cd /d "%PROJECT_DIR%"

where node >nul 2>nul || (
    echo [ERROR] Node.js not found in PATH.
    echo Install Node.js 20 LTS, reopen CMD/PowerShell and run this BAT again.
    echo.
    pause
    exit /b 1
)

where npm >nul 2>nul || (
    echo [ERROR] npm not found in PATH.
    echo Reinstall Node.js 20 LTS with npm enabled.
    echo.
    pause
    exit /b 1
)

where powershell >nul 2>nul || (
    echo [ERROR] PowerShell not found in PATH.
    echo.
    pause
    exit /b 1
)

set "APP_VERSION=unknown"
for /f "usebackq delims=" %%V in (`node -p "require('./package.json').version" 2^>nul`) do set "APP_VERSION=%%V"
if "%APP_VERSION%"=="" set "APP_VERSION=unknown"

title VKarmani Desktop v%APP_VERSION%

echo =========================================
echo      VKarmani Desktop v%APP_VERSION%
echo =========================================
echo.
echo [INFO] PROJECT_DIR=%PROJECT_DIR%

if /I "%MODE%"=="help" goto :help
if /I "%MODE%"=="web" goto :prepare_frontend_only
if /I "%MODE%"=="restart" goto :restart
if /I "%MODE%"=="cleanstart" goto :restart
if /I "%MODE%"=="build" goto :prepare_desktop
if /I "%MODE%"=="dev" goto :prepare_desktop
if /I "%MODE%"=="run" goto :prepare_desktop

echo [ERROR] Unknown mode: %MODE%
echo.
goto :help

:restart
call :kill_old_vkarmani
set "MODE=run"
goto :prepare_desktop

:prepare_frontend_only
call :ensure_frontend
if errorlevel 1 exit /b 1
echo [INFO] Starting web preview only...
echo [INFO] URL: http://127.0.0.1:5173/
echo.
call npm run dev
set "EXIT_CODE=%ERRORLEVEL%"
goto :finish

:prepare_desktop
where cargo >nul 2>nul || (
    echo [ERROR] Rust/Cargo not found in PATH.
    echo Install Rust stable from rustup.rs, reopen CMD/PowerShell and run this BAT again.
    echo.
    pause
    exit /b 1
)

call :ensure_xray
if errorlevel 1 exit /b 1

call :ensure_frontend
if errorlevel 1 exit /b 1

set "VKARMANI_XRAY_PATH=%PROJECT_DIR%\resources\core\windows\xray.exe"
set "RUST_BACKTRACE=1"
set "TAURI_DEV_HOST=127.0.0.1"
set "NPM_CONFIG_AUDIT=false"
set "NPM_CONFIG_FUND=false"

echo [INFO] VKARMANI_XRAY_PATH=%VKARMANI_XRAY_PATH%

if /I "%MODE%"=="build" goto :build_app
if /I "%MODE%"=="dev" goto :dev_app
if /I "%MODE%"=="run" goto :run_app

:run_app
call :kill_old_vkarmani
echo [INFO] Starting VKarmani app...
echo [INFO] Mode: desktop dev launcher
echo.
call npm run tauri:dev
set "EXIT_CODE=%ERRORLEVEL%"
goto :finish

:dev_app
call :kill_old_vkarmani
echo [INFO] Starting VKarmani app in developer mode...
echo.
call npm run tauri:dev
set "EXIT_CODE=%ERRORLEVEL%"
goto :finish

:build_app
echo [INFO] Building VKarmani installer/package...
echo.
call npm run tauri:build
set "EXIT_CODE=%ERRORLEVEL%"
goto :finish

:kill_old_vkarmani
echo [INFO] Closing old VKarmani processes before launch...
taskkill /F /IM vkarmani-desktop.exe >nul 2>nul
taskkill /F /IM VKarmani.exe >nul 2>nul
taskkill /F /IM "VKarmani Desktop.exe" >nul 2>nul
exit /b 0

:ensure_xray
set "XRAY_PATH=%PROJECT_DIR%\resources\core\windows\xray.exe"
if not exist "%PROJECT_DIR%\scripts\repair-xray-windows.ps1" (
    echo [ERROR] Missing script:
    echo %PROJECT_DIR%\scripts\repair-xray-windows.ps1
    echo.
    pause
    exit /b 1
)

echo [INFO] Checking bundled Xray-core resources...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJECT_DIR%\scripts\repair-xray-windows.ps1" -ProjectDir "%PROJECT_DIR%"
if errorlevel 1 (
    echo.
    echo [ERROR] Xray-core validation/repair failed.
    echo.
    pause
    exit /b 1
)

if not exist "%XRAY_PATH%" (
    echo [ERROR] xray.exe is still missing:
    echo %XRAY_PATH%
    echo.
    pause
    exit /b 1
)

if not exist "%PROJECT_DIR%\resources\core\windows\geoip.dat" echo [WARN] geoip.dat not found.
if not exist "%PROJECT_DIR%\resources\core\windows\geosite.dat" echo [WARN] geosite.dat not found.
if not exist "%PROJECT_DIR%\resources\core\windows\wintun.dll" echo [WARN] wintun.dll not found. TUN mode will not work.

exit /b 0

:ensure_frontend
if not exist ".env" if exist ".env.example" (
    echo [INFO] Creating .env from .env.example
    copy /Y ".env.example" ".env" >nul
)

set "REPAIRED=0"
if not exist "node_modules" (
    if exist "package-lock.json" (
        echo [INFO] Installing npm dependencies with npm ci...
        call npm ci --include=dev --no-audit --fund=false --registry=https://registry.npmjs.org/
    ) else (
        echo [INFO] Installing npm dependencies with npm install...
        call npm install --include=dev --no-audit --fund=false --registry=https://registry.npmjs.org/
    )
    if errorlevel 1 goto :npm_failed
    set "REPAIRED=1"
)

call :ensure_pkg "@vitejs/plugin-react/package.json" "npm install -D @vitejs/plugin-react@4.7.0 --no-audit --fund=false" "@vitejs/plugin-react"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "vite/package.json" "npm install -D vite@5.4.21 --no-audit --fund=false" "vite"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "typescript/package.json" "npm install -D typescript@5.9.3 --no-audit --fund=false" "typescript"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "react/jsx-runtime" "npm install react@18.3.1 react-dom@18.3.1 --no-audit --fund=false" "react/react-dom"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "lucide-react/package.json" "npm install lucide-react@0.511.0 --no-audit --fund=false" "lucide-react"
if errorlevel 1 goto :npm_failed
call :ensure_pkg "@tauri-apps/cli/package.json" "npm install -D @tauri-apps/cli@2.10.1 --no-audit --fund=false" "@tauri-apps/cli"
if errorlevel 1 goto :npm_failed

if "%REPAIRED%"=="1" (
    if exist "node_modules\.vite" rmdir /s /q "node_modules\.vite"
)

exit /b 0

:ensure_pkg
node -e "const spec=process.argv[1];const fs=require('fs');const path=require('path');try{require.resolve(spec);process.exit(0)}catch(e){}const p=path.join(process.cwd(),'node_modules',...spec.split('/'));process.exit((fs.existsSync(p)||fs.existsSync(p+'.js')||fs.existsSync(p+'.cjs')||fs.existsSync(p+'.mjs')||fs.existsSync(path.join(p,'package.json'))) ? 0 : 1)" "%~1" >nul 2>nul
if errorlevel 1 (
    echo [INFO] Missing or broken %~3. Repairing...
    call %~2 --registry=https://registry.npmjs.org/
    if errorlevel 1 exit /b 1
    set "REPAIRED=1"
)
exit /b 0

:npm_failed
echo.
echo [ERROR] npm dependency installation/repair failed.
echo.
pause
exit /b 1

:finish
echo.
if "%EXIT_CODE%"=="0" (
    echo [INFO] VKarmani process finished with code 0.
    echo [INFO] If the window closed immediately, run this BAT again or use START_VKarmani.bat restart.
) else (
    echo [ERROR] VKarmani exited with code %EXIT_CODE%.
)
echo.
pause
exit /b %EXIT_CODE%

:help
echo Usage:
echo   START_VKarmani.bat          Launch VKarmani desktop app
echo   START_VKarmani.bat restart  Kill old VKarmani process and launch again
echo   START_VKarmani.bat cleanstart Same as restart
echo   START_VKarmani.bat dev      Launch through Tauri dev
echo   START_VKarmani.bat web      Launch frontend only in browser
echo   START_VKarmani.bat build    Build installer/package
echo.
pause
exit /b 0
