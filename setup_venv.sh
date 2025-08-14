#!/usr/bin/env bash
# setup_venv.sh
# Creates a Python virtual environment and installs project requirements.

set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python3 not found. Please install Python 3.10+ and re-run." >&2
  exit 1
fi

VENV=".venv"
if [ -d "$VENV" ]; then
  echo "Virtual env already exists at $VENV. Remove it to recreate."
else
  python3 -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --upgrade pip wheel

if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt
else
  echo "requirements.txt not found; skipping pip install."
fi

# AWS CLI
if ! command -v aws >/dev/null 2>&1; then
  echo "WARNING: AWS CLI not found. Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
else
  aws --version
fi

# Automic bundle
if ! ls Automic*.zip >/dev/null 2>&1; then
  echo "WARNING: Automic bundle not found. Please place the Automic .zip in the project root."
else
  echo "Found Automic bundle: $(ls Automic*.zip | head -n1)"
fi

# Key file
if [ -z "${AUTOMIC_KEY_PATH:-}" ]; then
  echo "WARNING: Key not specified. Export AUTOMIC_KEY_PATH to your PEM/PPK path, e.g. export AUTOMIC_KEY_PATH=~/automic-key.pem"
else
  if [ -f "$AUTOMIC_KEY_PATH" ]; then
    echo "Using key at $AUTOMIC_KEY_PATH"
  else
    echo "WARNING: AUTOMIC_KEY_PATH points to a file that doesn't exist."
  fi
fi

echo
echo "Done. To activate this environment later:"
echo "  source .venv/bin/activate"
