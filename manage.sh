#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON="$ROOT/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  echo "Repository environment is missing. Run ./setup.sh first." >&2
  exit 2
fi
exec "$PYTHON" "$ROOT/wechat_manager.py" "$@"
