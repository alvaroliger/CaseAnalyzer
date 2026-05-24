@echo off
title CaseAnalyzer
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "VENV=%ROOT%.venv\Scripts"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONPATH=%ROOT%LeerDD"
set "MARKER=%ROOT%.wsl_tools_ready"

echo.
echo  CaseAnalyzer  ^|  Iniciando servicios...
echo  -----------------------------------------
echo.

REM ── Crear venv si no existe ───────────────────────────────────────────────────
if not exist "%VENV%\python.exe" (
    echo  [0/3] Creando entorno virtual .venv ...
    REM Preferir Python 3.11 (wheels precompilados para todas las dependencias)
    set "PY_CREATE="
    for %%P in (python3.11 python3.12 python3.13 python3 python) do (
        if not defined PY_CREATE (
            %%P --version >nul 2>&1
            if not errorlevel 1 set "PY_CREATE=%%P"
        )
    )
    if not defined PY_CREATE (
        echo  [ERROR] No se encontro Python 3. Instalalo antes de continuar.
        pause
        exit /b 1
    )
    %PY_CREATE% -m venv "%ROOT%.venv"
    if not exist "%VENV%\python.exe" (
        echo  [ERROR] No se pudo crear el venv con %PY_CREATE%.
        pause
        exit /b 1
    )
    echo  [0/3] Entorno virtual creado con %PY_CREATE%.
)

REM ── Instalar dependencias base ────────────────────────────────────────────────
echo  [1/3] Instalando dependencias Python...
"%VENV%\python.exe" -m pip install -r "%ROOT%LeerDD\requirements.txt" -q --disable-pip-version-check 2>nul
if errorlevel 1 echo  [WARN] Alguna dependencia base fallo. Continuando.

REM ── Intentar pytsk3 solo si hay wheel precompilado ────────────────────────────
"%VENV%\python.exe" -c "import pytsk3" >nul 2>&1
if errorlevel 1 (
    echo  [1/3] Buscando wheel de pytsk3...
    "%VENV%\python.exe" -m pip install pytsk3 --only-binary :all: -q --disable-pip-version-check >nul 2>&1
    if errorlevel 1 (
        echo  [1/3] pytsk3 no disponible para esta version de Python. Usando WSL.
    ) else (
        echo  [1/3] pytsk3 instalado.
    )
)

REM ── Setup WSL (solo si ya hay distro funcional) ───────────────────────────────
if exist "%MARKER%" goto :wsl_done

REM Verificar que WSL tiene una distribucion funcional con un echo simple
wsl -e bash -c "echo wsl_ok" >nul 2>&1
if errorlevel 1 (
    REM WSL sin distro: intentar instalar Ubuntu
    echo  [2/3] Instalando WSL Ubuntu (puede tardar varios minutos)...
    wsl --install -d Ubuntu
    REM Esperar y volver a probar
    timeout /t 20 /nobreak >nul
    wsl -e bash -c "echo wsl_ok" >nul 2>&1
    if errorlevel 1 (
        echo  [2/3] WSL no disponible. El analisis usara pytsk3 si esta instalado.
        goto :wsl_done
    )
)

echo  [2/3] Instalando herramientas forenses en WSL...
wsl -e bash -c "sudo apt-get update -qq 2>/dev/null && sudo apt-get install -y -qq sleuthkit ewf-tools 2>/dev/null"
if errorlevel 1 (
    echo  [2/3] No se pudieron instalar las herramientas WSL. Continuando sin ellas.
) else (
    echo  [2/3] Herramientas WSL listas.
    echo configurado> "%MARKER%"
)

:wsl_done

REM ── Liberar puerto 8001 si hay proceso previo ────────────────────────────────
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr " :8001 " ^| findstr LISTEN') do (
    taskkill /PID %%p /F >nul 2>&1
)

REM ── Backend Python ────────────────────────────────────────────────────────────
echo  [3/3] Backend Python  -^>  http://127.0.0.1:8001
start "CaseAnalyzer Backend" cmd /k "cd /d %ROOT%LeerDD && %VENV%\uvicorn.exe main:app --host 127.0.0.1 --port 8001 --no-access-log --log-level info"

timeout /t 3 /nobreak >nul

REM ── Laravel ──────────────────────────────────────────────────────────────────
echo  [3/3] Laravel          -^>  http://127.0.0.1:8000
echo.
echo  Cierra esta ventana para detener Laravel.
echo  Cierra la ventana "CaseAnalyzer Backend" para detener el backend.
echo.
cmd /k "cd /d %ROOT% && php artisan serve --host=127.0.0.1 --port=8000"

endlocal
