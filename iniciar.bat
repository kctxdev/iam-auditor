@echo off
rem IAM Permission Auditor - inicia a interface local (ou o CLI, se passar argumentos)
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (where python >nul 2>&1 && set "PY=python")
if not defined PY (
  echo Python 3 nao encontrado. Instale o Python 3.10+ em python.org
  pause
  exit /b 1
)

if not exist .venv (
  echo [1/2] Criando ambiente virtual...
  %PY% -m venv .venv
)
call .venv\Scripts\activate.bat

python -c "import boto3" >nul 2>&1
if errorlevel 1 (
  echo [2/2] Instalando dependencias...
  pip install -q -r requirements.txt
)

if "%~1"=="" (
  python -m iam_auditor --ui
) else (
  python -m iam_auditor %*
)
endlocal
