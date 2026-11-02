#!/usr/bin/env bash
# IAM Permission Auditor - inicia a interface local (ou o CLI, se passar argumentos)
#   ./iniciar.sh                 -> abre a interface no navegador
#   ./iniciar.sh --demo          -> roda no terminal com dados ficticios
#   ./iniciar.sh --profile x -v  -> roda no terminal na sua conta
set -e
cd "$(dirname "$0")"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then echo "Python 3 nao encontrado. Instale o Python 3.10+."; exit 1; fi

if [ ! -d .venv ]; then
  echo "[1/2] Criando ambiente virtual..."
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

if ! python -c "import boto3" 2>/dev/null; then
  echo "[2/2] Instalando dependencias..."
  pip install -q -r requirements.txt || echo "aviso: nao consegui instalar o boto3 (o modo demo continua funcionando)."
fi

if [ $# -eq 0 ]; then
  exec python -m iam_auditor --ui
else
  exec python -m iam_auditor "$@"
fi
