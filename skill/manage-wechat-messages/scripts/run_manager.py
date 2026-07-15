#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def find_root() -> Path:
    candidates = []
    configured = os.environ.get("WECHAT_MANAGER_HOME")
    if configured:
        candidates.append(Path(configured).expanduser())
    marker = Path(__file__).resolve().parents[1] / ".manager-home"
    if marker.is_file():
        try:
            candidates.append(Path(marker.read_text(encoding="utf-8").strip()))
        except OSError:
            pass
    candidates.extend([Path.cwd(), Path(__file__).resolve().parents[3]])
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "wechat_manager.py").is_file():
            return resolved
    raise SystemExit(
        "Repository not found. Run scripts/install_skill.py from the cloned wechat-message-manager repository."
    )


def manager_python(root: Path) -> Path:
    python = (
        root / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else root / ".venv" / "bin" / "python"
    )
    if not python.is_file() or (os.name != "nt" and not os.access(python, os.X_OK)):
        setup = ".\\setup.ps1" if os.name == "nt" else "./setup.sh"
        raise SystemExit(f"Repository environment not found. Run {setup} in the repository first.")
    return python


def main() -> int:
    root = find_root()
    return subprocess.run([str(manager_python(root)), str(root / "wechat_manager.py"), *sys.argv[1:]], cwd=root).returncode


if __name__ == "__main__":
    raise SystemExit(main())
