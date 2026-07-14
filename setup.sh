#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_SKILL=false
if [ "${1:-}" = "--install-skill" ]; then
  INSTALL_SKILL=true
elif [ "$#" -gt 0 ]; then
  echo "Usage: ./setup.sh [--install-skill]" >&2
  exit 2
fi

python3 -m venv "$ROOT/.venv"
PYTHON="$ROOT/.venv/bin/python"
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r "$ROOT/requirements.txt"

if [ "$INSTALL_SKILL" = true ]; then
  "$PYTHON" "$ROOT/scripts/install_skill.py"
fi

if ! "$PYTHON" "$ROOT/wechat_manager.py" preflight; then
  echo "Dependencies are installed. Preflight needs attention before configuration." >&2
fi
echo "Next: run wechat_manager.py preflight --configure, then follow the platform key instructions in README.md."
