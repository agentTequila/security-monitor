#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pip install --quiet -r requirements-dev.txt
python3 -m PyInstaller --onefile --clean --noconfirm --icon assets/icon.ico --name security-monitor --paths . security_monitor/__main__.py
echo "Built: dist/security-monitor"
