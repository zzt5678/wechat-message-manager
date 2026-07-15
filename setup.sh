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

python3 -c 'import platform,struct,sys; ok=sys.version_info >= (3,9) and sys.platform == "darwin" and struct.calcsize("P") == 8 and platform.machine().lower() in {"arm64","aarch64"}; raise SystemExit(0 if ok else 2)' || {
  echo "macOS setup requires Apple Silicon and native 64-bit Python 3.9 or newer." >&2
  exit 2
}
python3 -m venv "$ROOT/.venv"
PYTHON="$ROOT/.venv/bin/python"
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r "$ROOT/requirements.txt"
"$PYTHON" -m pip check

if [ "$INSTALL_SKILL" = true ]; then
  "$PYTHON" "$ROOT/scripts/install_skill.py"
fi

if ! "$PYTHON" "$ROOT/wechat_manager.py" preflight; then
  echo "Dependencies are installed. Preflight needs attention before configuration." >&2
fi
echo "After preflight is unambiguous and supported, run ./manage.sh preflight --configure and follow README.md."
