from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from manager_config import TOOL_VERSION


ROOT = Path(__file__).resolve().parent


def main() -> int:
    # Keep help, chat names, and JSON stable on English Windows consoles whose
    # legacy code page cannot encode Chinese or emoji.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) == 2 and sys.argv[1] in {"-V", "--version"}:
        print(TOOL_VERSION)
        return 0
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help", "help"}:
        print("""Local WeChat message manager (read-only message source)

Commands:
  --version                     print the tool version
  preflight [--configure]       discover databases without reading chat content
  capture-plan                  show the one-time key-capture impact
  capture --i-understand-read-process-memory
                                Windows: current-version read-only key recovery
  legacy-plan                   Windows: report why the 4.1.9 route is disabled
  capture-macos-plan            macOS: show signed-copy/spawn impact without acting
  capture-macos [options]       macOS: opt-in hook on a separately signed copy
  import-keys --file <json> [--delete-source]
                                Windows/macOS: verify and protect an existing key map
                                --delete-source is destructive and needs separate approval
  refresh [--mode full|incremental] [--dry-run]
                                after manual WeChat exit, refresh the private vault
  query <vault-cli arguments>   read only from the decrypted private vault

Examples:
  <wrapper> preflight --configure
  <wrapper> query status --format text
  <wrapper> query sessions --limit 20 --max-chars 30000 --format text --i-understand-message-content-output
  <wrapper> query history "群名" --limit 20 --max-chars 30000 --format text --i-understand-message-content-output
  <wrapper> query history --session-tag <opaque-tag> --limit 20 --max-chars 30000 --format text --i-understand-message-content-output

Use .\\manage.cmd as <wrapper> on Windows or ./manage.sh on macOS.
""")
        return 0
    command, *rest = sys.argv[1:]
    mapping = {
        "preflight": ("preflight.py", rest),
        "capture-plan": ("capture_keys_windows.py", []),
        "capture": ("capture_keys_windows.py", ["--execute", *rest]),
        "legacy-plan": ("legacy_windows.py", ["plan"]),
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
