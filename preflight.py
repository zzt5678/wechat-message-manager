from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import platform
from pathlib import Path
import subprocess
import sys

from manager_config import (
    CONFIG_FILE, CORE_DATABASES, PRIVATE_ROOT, account_tag, atomic_write_json,
    ensure_private_tree, public_path_label,
)


def discover_db_storages() -> list[Path]:
    candidates = [Path.home() / "xwechat_files", Path.home() / "Documents" / "xwechat_files"]
    if sys.platform == "darwin":
        candidates.insert(
            0,
            Path.home() / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
        )
    result: dict[str, Path] = {}
    for root in candidates:
        if not root.exists():
            continue
        for path in root.rglob("db_storage"):
            if path.is_dir():
                result[str(path.resolve()).casefold()] = path.resolve()
    return sorted(result.values(), key=lambda p: str(p).casefold())


def wechat_info() -> dict[str, object]:
    if sys.platform == "darwin":
        app = Path("/Applications/WeChat.app")
        completed = subprocess.run(
            ["mdls", "-raw", "-name", "kMDItemVersion", str(app)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        version = completed.stdout.strip().strip('"') if completed.returncode == 0 else "unknown"
        running = subprocess.run(["pgrep", "-x", "WeChat"], capture_output=True, text=True, check=False)
        return {
            "installed": app.exists(), "version": version, "installed_version": version,
            "running_version": version if running.returncode == 0 else None,
            "process_count": len(running.stdout.splitlines()) if running.returncode == 0 else 0,
        }
    exe = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Tencent/Weixin/Weixin.exe"
    version = "unknown"
    running_version = ""
    running_version_command = [
        "powershell", "-NoProfile", "-Command",
        "$p=Get-Process Weixin -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if($p){$p.MainModule.FileVersionInfo.FileVersion}",
    ]
    running_completed = subprocess.run(running_version_command, capture_output=True, text=True, timeout=10)
    if running_completed.returncode == 0:
        running_version = running_completed.stdout.strip()
    if exe.exists():
        command = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-Item -LiteralPath '{str(exe).replace(chr(39), chr(39)*2)}').VersionInfo.FileVersion",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if completed.returncode == 0 and completed.stdout.strip():
            version = completed.stdout.strip()
    running = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/NH"],
        capture_output=True, text=True, timeout=10,
    ).stdout.casefold().count("weixin.exe")
    return {
        "installed": exe.exists(),
        "version": running_version or version,
        "installed_version": version,
        "running_version": running_version or None,
        "process_count": running,
    }


def inspect(path: Path) -> dict[str, object]:
    dbs = sorted(
        str(file.relative_to(path)).replace("\\", "/")
        for file in path.rglob("*.db")
        if file.is_file() and not file.name.endswith(("-wal", "-shm"))
    )
    readable = True
    for rel in CORE_DATABASES:
        file = path / Path(rel)
        if not file.exists():
            continue
        try:
            with file.open("rb") as handle:
                handle.read(16)
        except OSError:
            readable = False
            break
    return {
        "account_tag": account_tag(path),
        "database_count": len(dbs),
        "readable": readable,
        "relative_databases": dbs,
        "core_present": [rel for rel in CORE_DATABASES if (path / Path(rel)).exists()],
        "core_missing": [rel for rel in CORE_DATABASES if not (path / Path(rel)).exists()],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Privacy-safe Windows WeChat database preflight")
    parser.add_argument("--configure", action="store_true", help="write the unique discovered source to the private config")
    parser.add_argument("--db-storage", type=Path, help="explicit db_storage directory when multiple accounts exist")
    args = parser.parse_args()
    storages = discover_db_storages()
    if args.db_storage is not None:
        selected = args.db_storage.expanduser().resolve()
        storages = [selected] if selected.is_dir() and selected.name == "db_storage" else []
    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.system(),
        "wechat": wechat_info(),
        "db_storage_count": len(storages),
        "accounts": [inspect(path) for path in storages],
        "private_root": public_path_label(PRIVATE_ROOT),
        "configured": False,
    }
    if args.configure:
        if len(storages) != 1:
            report["stop_reason"] = "DB_STORAGE_SELECTION_REQUIRED"
        else:
            details = report["accounts"][0]
            if not details["readable"] or details["core_missing"]:
                report["stop_reason"] = "CORE_DATABASE_PREFLIGHT_FAILED"
            else:
                ensure_private_tree()
                atomic_write_json(CONFIG_FILE, {
                    "schema_version": 1,
                    "db_base_path": str(storages[0]),
                    "account_tag": details["account_tag"],
                    "wechat_version": report["wechat"]["version"],
                    "decrypted_dir": str(PRIVATE_ROOT / "decrypted/current"),
                    "exports_dir": str(PRIVATE_ROOT / "exports"),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
                report["configured"] = True
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if len(storages) == 1 and not report.get("stop_reason") else 2


if __name__ == "__main__":
    raise SystemExit(main())
