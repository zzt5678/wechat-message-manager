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
    candidates.extend([Path.cwd(), Path(__file__).resolve().parents[3]])
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "wechat_manager.py").is_file():
            return resolved
    raise SystemExit("Set WECHAT_MANAGER_HOME to the cloned wechat-message-manager repository")


def main() -> int:
    root = find_root()
    return subprocess.run([sys.executable, str(root / "wechat_manager.py"), *sys.argv[1:]], cwd=root).returncode


if __name__ == "__main__":
    raise SystemExit(main())
