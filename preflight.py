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
    CONFIG_FILE, KEYS_FILE, MESSAGE_SHARD_PATTERN, PRIVATE_ROOT, REQUIRED_DATABASES,
    TOOL_VERSION, account_tag, atomic_write_json, configured_core_databases,
    discover_core_databases, ensure_private_tree, load_json, platform_support,
    public_path_label,
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
        root_resolved = root.resolve()
        for path in root.rglob("db_storage"):
            resolved = path.resolve()
            if path.is_dir() and not path.is_symlink() and resolved.is_relative_to(root_resolved):
                result[str(resolved).casefold()] = resolved
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
    install_candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tencent/Weixin/Weixin.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Tencent/Weixin/Weixin.exe",
        Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Tencent/Weixin/Weixin.exe",
    ]
    exe = next((path for path in install_candidates if path.is_file()), install_candidates[0])
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
        "installed": exe.exists() or bool(running_version),
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
    discovered = discover_core_databases(path)
    core_present = [
        rel for rel in discovered
        if (path / Path(rel)).is_file() and not (path / Path(rel)).is_symlink()
    ]
    message_shards = [rel for rel in core_present if MESSAGE_SHARD_PATTERN.fullmatch(rel)]
    core_missing = [
        rel for rel in REQUIRED_DATABASES
        if not (path / Path(rel)).is_file() or (path / Path(rel)).is_symlink()
    ]
    if not message_shards:
        core_missing.append("message/message_<N>.db")
    readable = True
    for rel in core_present:
        file = path / Path(rel)
        try:
            with file.open("rb") as handle:
                handle.read(16)
        except OSError:
            readable = False
            break
    nonempty_logs: list[str] = []
    for rel in core_present:
        database = path / Path(rel)
        for suffix in ("-wal", "-journal"):
            companion = database.with_name(database.name + suffix)
            try:
                if companion.stat().st_size > 0:
                    nonempty_logs.append(rel)
                    break
            except FileNotFoundError:
                pass
    return {
        "account_tag": account_tag(path),
        "database_count": len(dbs),
        "readable": readable,
        # Only the generic managed manifest is safe to expose. Other database
        # filenames are counted but may contain account-specific identifiers.
        "relative_databases": core_present,
        "core_present": core_present,
        "core_missing": core_missing,
        "message_shard_count": len(message_shards),
        "nonempty_transaction_log_databases": nonempty_logs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Privacy-safe local WeChat database preflight")
    parser.add_argument("--configure", action="store_true", help="write the unique discovered source to the private config")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--account-tag", help="select one discovered account without exposing its private path")
    selection.add_argument("--db-storage", type=Path, help="explicit db_storage directory for manual local use")
    args = parser.parse_args()
    support = platform_support()
    if not support["supported"]:
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "FAILED",
            "platform": support["platform"],
            "architecture": support["architecture"],
            "python_bits": support["python_bits"],
            "stop_reason": support["stop_reason"],
        }, ensure_ascii=False, indent=2))
        return 2
    storages = discover_db_storages()
    if args.db_storage is not None:
        selected = args.db_storage.expanduser().resolve()
        storages = [selected] if selected.is_dir() and selected.name == "db_storage" else []
    elif args.account_tag:
        storages = [path for path in storages if account_tag(path) == args.account_tag]
    configuration_present = CONFIG_FILE.is_file()
    existing_config: dict[str, object] = {}
    configuration_valid = False
    configuration_source_manifest_matches = False
    if configuration_present:
        try:
            loaded = load_json(CONFIG_FILE, {})
            if isinstance(loaded, dict) and loaded.get("db_base_path") and loaded.get("account_tag"):
                configured_core_databases(loaded)
                existing_config = loaded
                configuration_valid = True
                try:
                    configured_core_databases(loaded, verify_source=True)
                    configuration_source_manifest_matches = True
                except RuntimeError:
                    configuration_source_manifest_matches = False
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
            configuration_valid = False
    discovered_tags = {account_tag(path) for path in storages}
    report = {
        "tool_version": TOOL_VERSION,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.system(),
        "platform_support": support,
        "wechat": wechat_info(),
        "db_storage_count": len(storages),
        "accounts": [inspect(path) for path in storages],
        "private_root": public_path_label(PRIVATE_ROOT),
        "configured": configuration_present and configuration_valid and configuration_source_manifest_matches,
        "configuration_present": configuration_present,
        "configuration_valid": configuration_valid,
        "configuration_source_manifest_matches": configuration_source_manifest_matches,
        "configuration_written": False,
        "configuration_account_present_in_discovery": (
            existing_config.get("account_tag") in discovered_tags if existing_config else False
        ),
        "protected_key_store_marker_present": KEYS_FILE.is_file(),
    }
    if args.configure:
        if len(storages) != 1:
            report["stop_reason"] = "DB_STORAGE_SELECTION_REQUIRED"
        else:
            details = report["accounts"][0]
            if not details["readable"] or details["core_missing"]:
                report["stop_reason"] = "CORE_DATABASE_PREFLIGHT_FAILED"
            else:
                old_tag = existing_config.get("account_tag") if existing_config else None
                if configuration_present and not configuration_valid:
                    report["stop_reason"] = "INVALID_CONFIG_REQUIRES_NEW_VAULT"
                elif old_tag and old_tag != details["account_tag"]:
                    report["stop_reason"] = "ACCOUNT_CHANGE_REQUIRES_NEW_VAULT"
                else:
                    ensure_private_tree()
                    atomic_write_json(CONFIG_FILE, {
                        "schema_version": 2,
                        "db_base_path": str(storages[0]),
                        "account_tag": details["account_tag"],
                        "wechat_version": report["wechat"]["version"],
                        "core_databases": details["core_present"],
                        "decrypted_dir": str(PRIVATE_ROOT / "decrypted/current"),
                        "exports_dir": str(PRIVATE_ROOT / "exports"),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    })
                    report["configured"] = True
                    report["configuration_present"] = True
                    report["configuration_valid"] = True
                    report["configuration_source_manifest_matches"] = True
                    report["configuration_written"] = True
                    report["configuration_account_present_in_discovery"] = True
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if len(storages) == 1 and not report.get("stop_reason") else 2


if __name__ == "__main__":
    raise SystemExit(main())
