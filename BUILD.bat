@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo ============================================================
echo  PWNAudit NetScope - Full Build
echo  (icon -^> standalone .exe -^> Setup installer)
echo ============================================================
echo.

REM ── 0. Python ─────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not on PATH.
    echo         Install Python 3.10+ from https://www.python.org/downloads/
    echo         and tick "Add python.exe to PATH" during install.
    pause
    exit /b 1
)

REM ── 1. venv + deps ────────────────────────────────────────────────
if not exist venv (
    echo [1/5] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (echo [ERROR] venv creation failed. & pause & exit /b 1)
) else (
    echo [1/5] Virtual environment already present.
)

call venv\Scripts\activate.bat
echo [2/5] Installing build dependencies...
python -m pip install --upgrade --quiet pip
python -m pip install --quiet -r requirements.txt
python -m pip install --upgrade --quiet pyinstaller pillow
if errorlevel 1 (echo [ERROR] dependency install failed. & pause & exit /b 1)

REM ── 2. Generate the .ico ──────────────────────────────────────────
echo [3/5] Generating app icon...
python assets\make_icon.py
if errorlevel 1 (echo [ERROR] icon generation failed. & pause & exit /b 1)

REM ── 3. PyInstaller ────────────────────────────────────────────────
if exist build rmdir /s /q build
if exist dist\PWNAudit-NetScope.exe del /q dist\PWNAudit-NetScope.exe
if exist PWNAudit-NetScope.spec del /q PWNAudit-NetScope.spec

echo [4/5] Building standalone .exe (PyInstaller, ~60-120s)...
python -m PyInstaller --noconfirm --clean ^
    --name "PWNAudit-NetScope" ^
    --onefile ^
    --windowed ^
    --uac-admin ^
    --icon "assets\pwnaudit.ico" ^
    --collect-submodules scapy ^
    --hidden-import scapy.arch.windows ^
    --hidden-import scapy.layers.all ^
    --hidden-import scapy.layers.http ^
    --hidden-import scapy.layers.tls.all ^
    --hidden-import psutil._pswindows ^
    main.py

if errorlevel 1 (echo [ERROR] PyInstaller build failed. & pause & exit /b 1)
if not exist dist\PWNAudit-NetScope.exe (echo [ERROR] PyInstaller did not produce the .exe. & pause & exit /b 1)

REM ── 4. Inno Setup ─────────────────────────────────────────────────
echo [5/5] Looking for Inno Setup compiler...

set "ISCC="
for %%P in (
    "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
    "%ProgramFiles%\Inno Setup 6\ISCC.exe"
    "%ProgramFiles(x86)%\Inno Setup 5\ISCC.exe"
    "%ProgramFiles%\Inno Setup 5\ISCC.exe"
) do (
    if exist %%~P set "ISCC=%%~P"
)

if not defined ISCC (
    echo.
    echo ============================================================
    echo  PARTIAL BUILD COMPLETE
    echo  Standalone .exe ready: dist\PWNAudit-NetScope.exe
    echo.
    echo  Inno Setup is NOT installed, so the Setup wizard installer
    echo  was not built. To produce dist\PWNAudit-NetScope-Setup.exe
    echo  ^(the file you put on pwnaudit.com^):
    echo    1. Install Inno Setup from https://jrsoftware.org/isdl.php
    echo       ^(use the default options - "Inno Setup 6" works fine^)
    echo    2. Run BUILD.bat again
    echo ============================================================
    echo.
    pause
    exit /b 0
)

echo Found: !ISCC!
echo Compiling installer...
"!ISCC!" /Q "installer\installer.iss"
if errorlevel 1 (echo [ERROR] Inno Setup compilation failed. & pause & exit /b 1)

if not exist dist\PWNAudit-NetScope-Setup.exe (
    echo [ERROR] Inno Setup ran but the Setup .exe was not produced.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  BUILD COMPLETE
echo.
echo  Distributable installer:
echo    dist\PWNAudit-NetScope-Setup.exe
echo.
echo  Upload that file and link it from pwnaudit.com.
echo  When users run it, they get:
echo    - Wizard with Next / Install / Finish
echo    - Start Menu entry (appears in Windows Search)
echo    - Optional desktop shortcut
echo    - Add/Remove Programs entry with branded icon
echo    - App auto-launches on Finish
echo    - Prompt to install Npcap if missing
echo ============================================================
echo.
pause
