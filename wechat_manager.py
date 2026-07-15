from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def main() -> int:
    # Keep help, chat names, and JSON stable on English Windows consoles whose
    # legacy code page cannot encode Chinese or emoji.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help", "help"}:
        print("""Local WeChat message manager (read-only message source)

Commands:
  preflight [--configure]       discover databases without reading chat content
  capture-plan                  show the one-time key-capture impact
  capture --i-understand-read-process-memory
                                Windows: current-version read-only key recovery
  legacy-plan                   Windows: show the isolated 4.1.9 emergency route
  legacy-download [approval]    download and verify the pinned Tencent installer
  legacy-prepare [approval]     privately extract and back up the current launcher
  legacy-switch [approval]      after manual exit, snapshot DBs and stage 4.1.9
  legacy-capture [approval]     recover and HMAC-verify keys from signed 4.1.9
  legacy-restore [approval]     after manual exit, restore the current launcher
  legacy-verify-restored        verify the signed current runtime after login
  legacy-cleanup [approval]     remove only the added 4.1.9 program directory
  capture-macos [options]       macOS: opt-in hook on a separately signed copy
  import-keys --file <json> [--delete-source]
                                Windows/macOS: verify and protect an existing key map
  refresh [--mode full|incremental] [--dry-run]
                                decrypt/refresh the private vault with freshness gates
  query <vault-cli arguments>   read only from the decrypted private vault

Examples:
  python wechat_manager.py preflight
  python wechat_manager.py query sessions --limit 20 --format text
  python wechat_manager.py query history "群名" --limit 20 --format text
""")
        return 0
    command, *rest = sys.argv[1:]
    mapping = {
        "preflight": ("preflight.py", rest),
        "capture-plan": ("capture_keys_windows.py", []),
        "capture": ("capture_keys_windows.py", ["--execute", *rest]),
        "legacy-plan": ("legacy_windows.py", ["plan"]),
        "legacy-download": ("legacy_windows.py", ["download", *rest]),
        "legacy-prepare": ("legacy_windows.py", ["prepare", *rest]),
        "legacy-switch": ("legacy_windows.py", ["switch", *rest]),
        "legacy-capture": ("legacy_windows.py", ["capture", *rest]),
        "legacy-restore": ("legacy_windows.py", ["restore", *rest]),
        "legacy-verify-restored": ("legacy_windows.py", ["verify-restored", *rest]),
        "legacy-cleanup": ("legacy_windows.py", ["cleanup", *rest]),
        "capture-macos-plan": ("capture_keys_macos.py", []),
        "capture-macos": ("capture_keys_macos.py", ["--execute", *rest]),
        "import-keys": ("import_keys.py", rest),
        "refresh": ("refresh_vault.py", rest),
        "query": ("vault_query.py", rest),
    }
    if command not in mapping:
        print(f"Unknown command: {command}", file=sys.stderr)
        return 2
    script, args = mapping[command]
    return subprocess.run([sys.executable, str(ROOT / script), *args], cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
