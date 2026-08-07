#!/usr/bin/env bash
# run.sh — VibeCheck AI setup & launch
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[run.sh] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "[run.sh] Installing dependencies (this can take a few minutes the first time — sentence-transformers pulls in torch)..."
pip install --upgrade pip -q
pip install -r requirements.txt

echo "[run.sh] Generating adversarial test fixture..."
python3 create_payload.py

echo "[run.sh] Launching Streamlit command center..."
streamlit run app.py
