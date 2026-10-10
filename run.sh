#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then echo "Missing .venv; run ./setup.sh first." >&2; exit 1; fi
source .venv/bin/activate
exec uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8000}"
