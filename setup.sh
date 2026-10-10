#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
mkdir -p data reports evidence
if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from .env.example; edit it to configure AI (optional)."; fi
python -c 'from app.database import init_db; init_db(); print("Database initialized.")'
echo "Setup complete. Run ./run.sh"
